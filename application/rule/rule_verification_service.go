package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	ecommerceService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/ecommerce"
	itemSpecService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/item_specification"
	offerService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/offer"
	itemSpecificationDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item_specification"
	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/rule"
	ruleSpecDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/rule_specification"
	offerClient "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/api/offer"
	offerInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/offer"
	infrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/rule"
)

type RuleVerificationService interface {
	VerifyRules(ctx context.Context) error
	ProcessRules(ctx context.Context, offerId string) (bool, error)
}

type ruleVerificationService struct {
	ruleRepo         infrastructure.RuleRepository
	offerRepo        offerInfrastructure.IOfferRepository
	offerSvc         offerService.IOfferService
	offerClient      offerClient.OfferClient
	itemSpecSvc      itemSpecService.ItemSpecificationService
	ecommerceSvc     ecommerceService.EcommerceService
	ecommerceCredSvc ecommerceService.EcommerceCredentialsService
}

func NewRuleVerificationService(
	ruleRepo infrastructure.RuleRepository,
	offerRepo offerInfrastructure.IOfferRepository,
	offerSvc offerService.IOfferService,
	offerClient offerClient.OfferClient,
	itemSpecSvc itemSpecService.ItemSpecificationService,
	ecommerceSvc ecommerceService.EcommerceService,
	ecommerceCredSvc ecommerceService.EcommerceCredentialsService,
) RuleVerificationService {
	return &ruleVerificationService{
		ruleRepo:         ruleRepo,
		offerRepo:        offerRepo,
		offerSvc:         offerSvc,
		offerClient:      offerClient,
		itemSpecSvc:      itemSpecSvc,
		ecommerceSvc:     ecommerceSvc,
		ecommerceCredSvc: ecommerceCredSvc,
	}
}

func (s *ruleVerificationService) VerifyRules(ctx context.Context) error {
	rules, err := s.ruleRepo.GetAllRules()
	if err != nil {
		return fmt.Errorf("failed to get rules: %w", err)
	}

	groupedRules := groupRulesByOffer(rules)

	for offerId := range groupedRules {
		if err := s.processOfferRules(ctx, offerId); err != nil {
			fmt.Printf("Error processing rules for offer %s: %v\n", offerId, err)
		}
	}

	return nil
}

func (s *ruleVerificationService) processOfferRules(ctx context.Context, offerId string) error {
	offer, err := s.offerSvc.GetOfferById(ctx, offerId)
	if err != nil {
		return fmt.Errorf("failed to get offer state: %w", err)
	}

	if offer.State == "Offered" {
		fmt.Printf("Skipping offer %s: already in Offered state\n", offerId)
		return nil
	}

	hasActiveRule, err := s.ProcessRules(ctx, offerId)
	if err != nil {
		return fmt.Errorf("failed to process rules: %w", err)
	}

	if hasActiveRule {
		fmt.Printf("Processing active rules for offer %s\n", offerId)
		if err := s.sendTokenAndUpdateState(ctx, offerId); err != nil {
			return fmt.Errorf("failed to send token and update state: %w", err)
		}
	}

	return nil
}

func (s *ruleVerificationService) sendTokenAndUpdateState(ctx context.Context, offerId string) error {
	token, err := s.offerClient.GetToken(ctx, offerId)
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}

	if err := s.offerClient.SendToken(ctx, offerId, token); err != nil {
		return fmt.Errorf("failed to send token: %w", err)
	}

	if err := s.offerSvc.UpdateOfferState(ctx, offerId, "Offered"); err != nil {
		return fmt.Errorf("failed to update offer state: %w", err)
	}

	return nil
}

func (s *ruleVerificationService) ProcessRules(ctx context.Context, offerId string) (bool, error) {
	rules, err := s.ruleRepo.GetOfferRules(offerId)
	if err != nil {
		return false, fmt.Errorf("failed to get offer rules: %w", err)
	}

	hasActiveRule := false

	for _, rule := range rules {
		if err := s.processRule(ctx, &rule, &hasActiveRule); err != nil {
			fmt.Printf("Error processing rule %s: %v\n", rule.RuleId, err)
		}
	}

	return hasActiveRule, nil
}

func (s *ruleVerificationService) processRule(ctx context.Context, rule *domain.Rule, hasActiveRule *bool) error {
	specifications, err := s.ruleRepo.GetRulesSpecification(rule.RuleId)
	if err != nil {
		return fmt.Errorf("failed to get rule specifications: %w", err)
	}

	itemSpecs, err := s.itemSpecSvc.GetItemSpecByOfferId(ctx, rule.OfferId, rule.PosId)
	if err != nil {
		return fmt.Errorf("failed to get item specifications: %w", err)
	}

	isActive := evaluateRuleSpecifications(ctx, specifications, itemSpecs, rule.PosId, s)
	rule.State = getRuleState(isActive)

	if err := s.ruleRepo.SaveRule(ctx, rule); err != nil {
		return fmt.Errorf("failed to save rule state: %w", err)
	}

	if isActive {
		*hasActiveRule = true
	}

	return nil
}

func evaluateRuleSpecifications(ctx context.Context, specifications []ruleSpecDomain.RuleSpecification, itemSpecs []itemSpecificationDomain.ItemSpecification, posId string, s *ruleVerificationService) bool {
	for _, spec := range specifications {
		if s.verifySpecification(ctx, spec, itemSpecs, posId) {
			return true
		}
	}
	return false
}

func (s *ruleVerificationService) verifySpecification(ctx context.Context, spec ruleSpecDomain.RuleSpecification, itemSpecs []itemSpecificationDomain.ItemSpecification, posId string) bool {
	if spec.Parameter == "current date" {
		return verifyDateSpecification(spec)
	}

	if spec.Parameter == "availability" {
		var matchingSpec *itemSpecificationDomain.ItemSpecification
		for _, itemSpec := range itemSpecs {
			if itemSpec.Id == spec.RuleSpecificationId {
				matchingSpec = &itemSpec
				break
			}
		}

		if matchingSpec == nil {
			return false
		}

		if matchingSpec.IsExternal {
			credentials, err := s.ecommerceCredSvc.GetCredentials(ctx, posId)
			if err != nil {
				fmt.Printf("Error getting ecommerce credentials: %v\n", err)
				return false
			}

			itemId := strings.TrimPrefix(matchingSpec.ItemId, "kivio-ecommerce~")
			rawData, err := s.ecommerceSvc.GetItemsRaw(ctx, credentials.ApiURL, credentials.ApiKey, 1, 100)
			if err != nil {
				fmt.Printf("Error getting ecommerce data: %v\n", err)
				return false
			}

			var items []map[string]interface{}
			if err := json.Unmarshal(rawData, &items); err != nil {
				fmt.Printf("Error parsing ecommerce data: %v\n", err)
				return false
			}

			itemIdInt, err := strconv.Atoi(itemId)
			if err != nil {
				fmt.Printf("Error converting itemId '%s' to int: %v\n", itemId, err)
				return false
			}

			var matchingItem map[string]interface{}
			for _, item := range items {
				if id, ok := item["id"].(float64); ok && int(id) == itemIdInt {
					matchingItem = item
					break
				}
			}

			if matchingItem == nil {
				return false
			}

			if stock, ok := matchingItem["stock_quantity"].(float64); ok {
				return verifyNumericValue(stock, spec)
			}
			return false
		}

		return verifyNumericSpecification(spec)
	}

	var matchingSpec *itemSpecificationDomain.ItemSpecification
	for _, itemSpec := range itemSpecs {
		if itemSpec.Id == spec.RuleSpecificationId {
			matchingSpec = &itemSpec
			break
		}
	}

	if matchingSpec == nil || !matchingSpec.IsExternal {
		return false
	}

	credentials, err := s.ecommerceCredSvc.GetCredentials(ctx, posId)
	if err != nil {
		fmt.Printf("Error getting ecommerce credentials: %v\n", err)
		return false
	}

	itemId := strings.TrimPrefix(matchingSpec.ItemId, "kivio-ecommerce~")
	rawData, err := s.ecommerceSvc.GetItemsRaw(ctx, credentials.ApiURL, credentials.ApiKey, 1, 100)
	if err != nil {
		fmt.Printf("Error getting ecommerce data: %v\n", err)
		return false
	}

	var items []map[string]interface{}
	if err := json.Unmarshal(rawData, &items); err != nil {
		fmt.Printf("Error parsing ecommerce data: %v\n", err)
		return false
	}

	itemIdInt, err := strconv.Atoi(itemId)
	if err != nil {
		fmt.Printf("Error converting itemId '%s' to int: %v\n", itemId, err)
		return false
	}

	var matchingItem map[string]interface{}
	for _, item := range items {
		if id, ok := item["id"].(float64); ok && int(id) == itemIdInt {
			matchingItem = item
			break
		}
	}

	if matchingItem == nil {
		return false
	}

	switch spec.Parameter {
	case "StockQuantity":
		if stock, ok := matchingItem["stock_quantity"].(float64); ok {
			return verifyNumericValue(stock, spec)
		}
	case "Price", "OldPrice":
		if price, ok := matchingItem["price"].(float64); ok {
			return verifyNumericValue(price, spec)
		}
	case "Published", "VisibleIndividually", "IsFreeShipping":
		if published, ok := matchingItem["published"].(bool); ok {
			return verifyBooleanValue(published, spec)
		}
	case "AvailableStartDate", "AvailableEndDate":
		if dateStr, ok := matchingItem["available_date"].(string); ok {
			date, err := time.Parse(time.RFC3339, dateStr)
			if err != nil {
				return false
			}
			return verifyDateValue(date, spec)
		}
	case "Tags":
		if tags, ok := matchingItem["tags"].([]interface{}); ok {
			tagStr := strings.Join(interfaceSliceToStringSlice(tags), ",")
			return verifyCategoryValue(tagStr, spec)
		}
	}
	return false
}

func verifyDateValue(value time.Time, spec ruleSpecDomain.RuleSpecification) bool {
	parameterDate, err := time.Parse(time.RFC1123, spec.Type)
	if err != nil {
		return false
	}

	switch spec.Operator {
	case "=":
		return value.Equal(parameterDate)
	case "!=":
		return !value.Equal(parameterDate)
	case ">":
		return value.After(parameterDate)
	case "<":
		return value.Before(parameterDate)
	case ">=":
		return value.After(parameterDate) || value.Equal(parameterDate)
	case "<=":
		return value.Before(parameterDate) || value.Equal(parameterDate)
	default:
		return false
	}
}

func verifyCategoryValue(value string, spec ruleSpecDomain.RuleSpecification) bool {
	value = strings.ToLower(value)
	parameterValue := strings.ToLower(spec.Type)

	switch spec.Operator {
	case "está en":
		return strings.Contains(value, parameterValue)
	case "no está en":
		return !strings.Contains(value, parameterValue)
	default:
		return false
	}
}

func interfaceSliceToStringSlice(slice []interface{}) []string {
	result := make([]string, len(slice))
	for i, v := range slice {
		result[i] = fmt.Sprint(v)
	}
	return result
}

func verifyNumericValue(value float64, spec ruleSpecDomain.RuleSpecification) bool {
	parameterValue, err := strconv.ParseFloat(spec.Type, 64)
	if err != nil {
		return false
	}

	switch spec.Operator {
	case "=":
		return value == parameterValue
	case "!=":
		return value != parameterValue
	case ">":
		return value > parameterValue
	case "<":
		return value < parameterValue
	case ">=":
		return value >= parameterValue
	case "<=":
		return value <= parameterValue
	default:
		return false
	}
}

func verifyBooleanValue(value bool, spec ruleSpecDomain.RuleSpecification) bool {
	parameterValue, err := strconv.ParseBool(spec.Type)
	if err != nil {
		return false
	}

	switch spec.Operator {
	case "=":
		return value == parameterValue
	case "!=":
		return value != parameterValue
	default:
		return false
	}
}

func verifyDateSpecification(spec ruleSpecDomain.RuleSpecification) bool {
	currentDate := time.Now().UTC()

	dateStr := spec.Type
	if idx := strings.Index(dateStr, "("); idx != -1 {
		dateStr = strings.TrimSpace(dateStr[:idx])
	}

	formats := []string{
		"Mon Jan 02 2006 15:04:05 GMT-0700",
		"Mon Jan 02 2006 15:04:05 GMT-0500",
		"2006-01-02T15:04:05Z",
	}

	var parameterDate time.Time
	var err error

	for _, format := range formats {
		parameterDate, err = time.Parse(format, dateStr)
		if err == nil {
			break
		}
	}

	if err != nil {
		fmt.Printf("Error parsing date '%s': %v\n", dateStr, err)
		return false
	}

	switch spec.Operator {
	case "=":
		return currentDate.Equal(parameterDate)
	case "!=":
		return !currentDate.Equal(parameterDate)
	case ">":
		return currentDate.After(parameterDate)
	case "<":
		return currentDate.Before(parameterDate)
	case ">=":
		return currentDate.After(parameterDate) || currentDate.Equal(parameterDate)
	case "<=":
		return currentDate.Before(parameterDate) || currentDate.Equal(parameterDate)
	default:
		return false
	}
}

func verifyNumericSpecification(spec ruleSpecDomain.RuleSpecification) bool {
	value, err := strconv.ParseFloat(spec.Type, 64)
	if err != nil {
		return false
	}

	parameterValue, err := strconv.ParseFloat(spec.Type, 64)
	if err != nil {
		return false
	}

	switch spec.Operator {
	case "=":
		return value == parameterValue
	case "!=":
		return value != parameterValue
	case ">":
		return value > parameterValue
	case "<":
		return value < parameterValue
	case ">=":
		return value >= parameterValue
	case "<=":
		return value <= parameterValue
	default:
		return false
	}
}

func verifyCurrencySpecification(spec ruleSpecDomain.RuleSpecification) bool {
	valueStr := strings.ReplaceAll(spec.Type, "$", "")
	valueStr = strings.ReplaceAll(valueStr, ",", "")
	value, err := strconv.ParseFloat(valueStr, 64)
	if err != nil {
		return false
	}

	parameterStr := strings.ReplaceAll(spec.Type, "$", "")
	parameterStr = strings.ReplaceAll(parameterStr, ",", "")
	parameterValue, err := strconv.ParseFloat(parameterStr, 64)
	if err != nil {
		return false
	}

	switch spec.Operator {
	case "=":
		return value == parameterValue
	case "!=":
		return value != parameterValue
	case ">":
		return value > parameterValue
	case "<":
		return value < parameterValue
	case ">=":
		return value >= parameterValue
	case "<=":
		return value <= parameterValue
	default:
		return false
	}
}

func verifyBooleanSpecification(spec ruleSpecDomain.RuleSpecification) bool {
	value, err := strconv.ParseBool(spec.Type)
	if err != nil {
		return false
	}

	parameterValue, err := strconv.ParseBool(spec.Type)
	if err != nil {
		return false
	}

	switch spec.Operator {
	case "=":
		return value == parameterValue
	case "!=":
		return value != parameterValue
	default:
		return false
	}
}

func verifyCategorySpecification(spec ruleSpecDomain.RuleSpecification) bool {
	value := strings.ToLower(spec.Type)
	parameterValue := strings.ToLower(spec.Type)

	switch spec.Operator {
	case "está en":
		return strings.Contains(parameterValue, value)
	case "no está en":
		return !strings.Contains(parameterValue, value)
	default:
		return false
	}
}

func groupRulesByOffer(rules []domain.Rule) map[string][]domain.Rule {
	grouped := make(map[string][]domain.Rule)
	for _, rule := range rules {
		grouped[rule.OfferId] = append(grouped[rule.OfferId], rule)
	}
	return grouped
}

func getRuleState(isActive bool) string {
	if isActive {
		return "Active"
	}
	return "Inactive"
}
