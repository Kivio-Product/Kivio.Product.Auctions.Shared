package services

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	offerService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/offer"
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
	ruleRepo    infrastructure.RuleRepository
	offerRepo   offerInfrastructure.IOfferRepository
	offerSvc    offerService.IOfferService
	offerClient offerClient.OfferClient
}

func NewRuleVerificationService(
	ruleRepo infrastructure.RuleRepository,
	offerRepo offerInfrastructure.IOfferRepository,
	offerSvc offerService.IOfferService,
	offerClient offerClient.OfferClient,
) RuleVerificationService {
	return &ruleVerificationService{
		ruleRepo:    ruleRepo,
		offerRepo:   offerRepo,
		offerSvc:    offerSvc,
		offerClient: offerClient,
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

	isActive := evaluateRuleSpecifications(specifications)
	rule.State = getRuleState(isActive)

	if err := s.ruleRepo.SaveRule(ctx, rule); err != nil {
		return fmt.Errorf("failed to save rule state: %w", err)
	}

	if isActive {
		*hasActiveRule = true
	}

	return nil
}

func evaluateRuleSpecifications(specifications []ruleSpecDomain.RuleSpecification) bool {
	for _, spec := range specifications {
		if verifySpecification(spec) {
			return true
		}
	}
	return false
}

func getRuleState(isActive bool) string {
	if isActive {
		return "Active"
	}
	return "Inactive"
}

func verifySpecification(spec ruleSpecDomain.RuleSpecification) bool {
	switch spec.Parameter {
	case "current date":
		return verifyDateSpecification(spec)
	case "StockQuantity", "availability":
		return verifyNumericSpecification(spec)
	case "Price", "OldPrice":
		return verifyCurrencySpecification(spec)
	case "Published", "VisibleIndividually", "IsFreeShipping":
		return verifyBooleanSpecification(spec)
	case "AvailableStartDate", "AvailableEndDate":
		return verifyDateSpecification(spec)
	case "Tags":
		return verifyCategorySpecification(spec)
	default:
		return false
	}
}

func verifyDateSpecification(spec ruleSpecDomain.RuleSpecification) bool {
	currentDate := time.Now().UTC()
	parameterDate, err := time.Parse(time.RFC1123, spec.Type)
	if err != nil {
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
