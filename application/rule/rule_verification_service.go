package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	ecommerceService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/ecommerce"
	itemSpecService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/item_specification"
	applicationLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/logging"
	offerService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/offer"
	strategyApplication "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/strategy"
	itemSpecificationDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item_specification"
	"github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/logging"
	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/rule"
	ruleSpecDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/rule_specification"
	offerClient "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/api/offer"
	infrastructureLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/logging"
	offerInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/offer"
	infrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/rule"
)

type RuleVerificationService interface {
	VerifyRules(ctx context.Context, pointOfSaleId string) error
	ProcessRules(ctx context.Context, offerId string) (bool, error)
}

type ruleVerificationService struct {
	ruleRepo          infrastructure.RuleRepository
	offerRepo         offerInfrastructure.IOfferRepository
	offerSvc          offerService.IOfferService
	offerClient       offerClient.OfferClient
	itemSpecSvc       itemSpecService.ItemSpecificationService
	ecommerceSvc      ecommerceService.EcommerceService
	ecommerceCredSvc  ecommerceService.EcommerceCredentialsService
	itemSourceFactory *strategyApplication.ItemSourceFactory
	serviceLogger     *applicationLogging.ServiceLogger
	eventLogger       *logging.DomainEventLogger
}

func NewRuleVerificationService(
	ruleRepo infrastructure.RuleRepository,
	offerRepo offerInfrastructure.IOfferRepository,
	offerSvc offerService.IOfferService,
	offerClient offerClient.OfferClient,
	itemSpecSvc itemSpecService.ItemSpecificationService,
	ecommerceSvc ecommerceService.EcommerceService,
	ecommerceCredSvc ecommerceService.EcommerceCredentialsService,
	itemSourceFactory *strategyApplication.ItemSourceFactory,
) RuleVerificationService {
	loggerRepo := infrastructureLogging.GetLoggerRepository()
	serviceLogger := applicationLogging.NewServiceLogger(loggerRepo, "RuleVerificationService")
	eventLogger := logging.NewDomainEventLogger(loggerRepo.GetLogger())

	return &ruleVerificationService{
		ruleRepo:          ruleRepo,
		offerRepo:         offerRepo,
		offerSvc:          offerSvc,
		offerClient:       offerClient,
		itemSpecSvc:       itemSpecSvc,
		ecommerceSvc:      ecommerceSvc,
		ecommerceCredSvc:  ecommerceCredSvc,
		itemSourceFactory: itemSourceFactory,
		serviceLogger:     serviceLogger,
		eventLogger:       eventLogger,
	}
}

func (s *ruleVerificationService) VerifyRules(ctx context.Context, pointOfSaleId string) error {
	rules, err := s.ruleRepo.GetRulesByPosId(ctx, pointOfSaleId)
	if err != nil {
		return fmt.Errorf("fallo al obtener reglas para el punto de venta %s: %w", pointOfSaleId, err)
	}

	groupedRules := groupRulesByOffer(rules)

	errChan := make(chan error, len(groupedRules))
	var wg sync.WaitGroup

	semaphore := make(chan struct{}, 10)

	for offerId := range groupedRules {
		wg.Add(1)
		go func(offerId string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if err := s.processOfferRules(ctx, offerId); err != nil {
				errChan <- fmt.Errorf("error al procesar reglas para la oferta %s: %w", offerId, err)
			}
		}(offerId)
	}

	wg.Wait()
	close(errChan)

	return nil
}

func (s *ruleVerificationService) processOfferRules(ctx context.Context, offerId string) error {
	offer, err := s.offerSvc.GetOfferById(ctx, offerId)
	if err != nil {
		return fmt.Errorf("fallo al obtener la oferta con ID %s: %w", offerId, err)
	}

	if offer.State == "Offered" || offer.State == "Closed" {
		fmt.Printf("Omitiendo oferta %s: ya está en estado 'Offered'\n", offerId)
		return nil
	}

	hasActiveRule, err := s.ProcessRules(ctx, offerId)
	if err != nil {
		return fmt.Errorf("fallo al procesar reglas para la oferta %s: %w", offerId, err)
	}

	if hasActiveRule {
		fmt.Printf("Reglas activas encontradas para la oferta %s, enviando token y actualizando estado\n", offerId)
		if err := s.sendTokenAndUpdateState(ctx, offerId); err != nil {
			return fmt.Errorf("fallo al enviar token y actualizar el estado para la oferta %s: %w", offerId, err)
		}
	}

	return nil
}

func (s *ruleVerificationService) sendTokenAndUpdateState(ctx context.Context, offerId string) error {
	token, err := s.offerClient.GetToken(ctx, offerId)
	if err != nil {
		return fmt.Errorf("fallo al obtener el token para la oferta %s: %w", offerId, err)
	}

	if err := s.offerClient.SendToken(ctx, offerId, token); err != nil {
		return fmt.Errorf("fallo al enviar el token para la oferta %s: %w", offerId, err)
	}

	if err := s.offerSvc.UpdateOfferState(ctx, offerId, "Offered"); err != nil {
		return fmt.Errorf("fallo al actualizar el estado de la oferta %s a 'Offered': %w", offerId, err)
	}

	return nil
}

func (s *ruleVerificationService) ProcessRules(ctx context.Context, offerId string) (bool, error) {
	start := time.Now()
	s.serviceLogger.LogServiceStart(ctx, "ProcessRules", map[string]interface{}{
		"offer_id": offerId,
	})

	rules, err := s.ruleRepo.GetOfferRules(offerId)
	if err != nil {
		s.serviceLogger.LogServiceError(ctx, "ProcessRules", err, map[string]interface{}{
			"offer_id": offerId,
			"error":    "failed_to_get_rules",
		})
		return false, fmt.Errorf("fallo al obtener reglas para la oferta %s: %w", offerId, err)
	}

	s.serviceLogger.LogBusinessRule(ctx, "RuleEvaluation", true, map[string]interface{}{
		"offer_id":    offerId,
		"rules_count": len(rules),
		"rule_ids":    getRuleIds(rules),
	})

	var (
		wg            sync.WaitGroup
		hasActiveRule bool
	)

	semaphore := make(chan struct{}, 5)

	for i := range rules {
		wg.Add(1)
		go func(rule *domain.Rule) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if err := s.processRule(ctx, rule, &hasActiveRule); err != nil {
				fmt.Printf("Error al procesar la regla %s para la oferta %s: %v\n", rule.RuleId, offerId, err)
			}
		}(&rules[i])
	}

	wg.Wait()

	s.serviceLogger.LogServiceEnd(ctx, "ProcessRules", time.Since(start), map[string]interface{}{
		"offer_id":        offerId,
		"rules_count":     len(rules),
		"has_active_rule": hasActiveRule,
		"success":         true,
	})

	return hasActiveRule, nil
}

func (s *ruleVerificationService) processRule(ctx context.Context, rule *domain.Rule, hasActiveRule *bool) error {
	var mu sync.Mutex
	oldState := rule.State

	specifications, err := s.ruleRepo.GetRulesSpecification(rule.RuleId)
	if err != nil {
		s.serviceLogger.LogServiceError(ctx, "ProcessRule", err, map[string]interface{}{
			"rule_id":  rule.RuleId,
			"offer_id": rule.OfferId,
			"error":    "failed_to_get_rule_specifications",
		})
		return fmt.Errorf("fallo al obtener especificaciones para la regla %s: %w", rule.RuleId, err)
	}

	itemSpecs, err := s.itemSpecSvc.GetItemSpecByOfferId(ctx, rule.OfferId, rule.PosId)
	if err != nil {
		s.serviceLogger.LogServiceError(ctx, "ProcessRule", err, map[string]interface{}{
			"rule_id":  rule.RuleId,
			"offer_id": rule.OfferId,
			"pos_id":   rule.PosId,
			"error":    "failed_to_get_item_specifications",
		})
		return fmt.Errorf("fallo al obtener especificaciones de artículo para la oferta %s y POS %s: %w", rule.OfferId, rule.PosId, err)
	}

	isActive := s.evaluateRuleSpecifications(ctx, specifications, itemSpecs, rule.ItemSpecificationId, rule.PosId)
	rule.State = getRuleState(isActive)

	if err := s.ruleRepo.SaveRule(ctx, rule); err != nil {
		s.serviceLogger.LogServiceError(ctx, "ProcessRule", err, map[string]interface{}{
			"rule_id":  rule.RuleId,
			"offer_id": rule.OfferId,
			"error":    "failed_to_save_rule",
		})
		return fmt.Errorf("fallo al guardar el estado para la regla %s: %w", rule.RuleId, err)
	}

	if oldState != rule.State {
		s.eventLogger.LogRuleStateChange(ctx, rule.RuleId, oldState, rule.State)
	}

	s.serviceLogger.LogBusinessRule(ctx, "RuleEvaluated", isActive, map[string]interface{}{
		"rule_id":              rule.RuleId,
		"offer_id":             rule.OfferId,
		"pos_id":               rule.PosId,
		"old_state":            oldState,
		"new_state":            rule.State,
		"is_active":            isActive,
		"specifications_count": len(specifications),
		"item_specs_count":     len(itemSpecs),
	})

	if isActive {
		mu.Lock()
		*hasActiveRule = true
		mu.Unlock()
	}

	return nil
}

func (s *ruleVerificationService) evaluateRuleSpecifications(
	ctx context.Context,
	specifications []ruleSpecDomain.RuleSpecification,
	itemSpecs []itemSpecificationDomain.ItemSpecification,
	itemSpecId string,
	posId string,
) bool {
	for _, spec := range specifications {
		if spec.Parameter == "offerType" {
			continue
		}
		if !s.verifySpecification(ctx, spec, itemSpecs, itemSpecId, posId) {
			return false
		}
	}
	return true
}

func (s *ruleVerificationService) verifySpecification(
	ctx context.Context,
	spec ruleSpecDomain.RuleSpecification,
	itemSpecs []itemSpecificationDomain.ItemSpecification,
	itemSpecId string,
	posId string,
) bool {
	var matchingSpec *itemSpecificationDomain.ItemSpecification
	for _, itemSpec := range itemSpecs {
		if itemSpec.Id == itemSpecId {
			matchingSpec = &itemSpec
			break
		}
	}

	if spec.Parameter == "current date" {
		return verifyDateSpecification(spec)
	}

	if spec.Parameter == "availability" {
		if matchingSpec == nil {
			fmt.Printf("No se encontró especificación de artículo coincidente para el ID: %s\n", itemSpecId)
			return false
		}
		expected, err := strconv.ParseInt(spec.Type, 10, 64)
		if err != nil {
			fmt.Printf("Error al parsear spec.Type '%s' como int64 para availability: %v\n", spec.Type, err)
			return false
		}
		switch spec.Operator {
		case "=":
			return matchingSpec.Availability == expected
		case "!=":
			return matchingSpec.Availability != expected
		case ">":
			return matchingSpec.Availability > expected
		case "<":
			return matchingSpec.Availability < expected
		case ">=":
			return matchingSpec.Availability >= expected
		case "<=":
			return matchingSpec.Availability <= expected
		default:
			fmt.Printf("Operador desconocido '%s' para comparación de availability.\n", spec.Operator)
			return false
		}
	}

	if matchingSpec == nil {
		fmt.Printf("No se encontró especificación de artículo coincidente para el ID: %s\n", itemSpecId)
		return false
	}

	if !matchingSpec.IsExternal {
		fmt.Printf("La especificación del artículo %s no es externa, omitiendo las comprobaciones de e-commerce.\n", matchingSpec.Id)
		return false
	}

	source := string(matchingSpec.GetSource())
	strategy, err := s.itemSourceFactory.GetStrategyByItemSpec(ctx, source, posId)
	if err != nil {
		fmt.Printf("Error al obtener estrategia para la fuente '%s' y POS %s: %v\n", source, posId, err)
		return false
	}

	item, err := strategy.GetItemByID(ctx, matchingSpec.ItemId)
	if err != nil {
		fmt.Printf("Error al obtener item %s usando estrategia: %v\n", matchingSpec.ItemId, err)
		return false
	}

	if item == nil {
		fmt.Printf("No se encontró artículo para el ID: %s. Eliminando especificación del artículo.\n", matchingSpec.ItemId)
		if err := s.itemSpecSvc.Delete(ctx, matchingSpec.Id); err != nil {
			fmt.Printf("Error al eliminar la especificación del artículo %s: %v\n", matchingSpec.Id, err)
		} else {
			fmt.Printf("Especificación del artículo %s eliminada exitosamente.\n", matchingSpec.Id)
		}
		return false
	}

	if matchingSpec.GetSource() == itemSpecificationDomain.SourceEcommerce {
		credentials, err := s.ecommerceCredSvc.GetCredentials(ctx, posId)
		if err != nil {
			fmt.Printf("Error al obtener credenciales de e-commerce para POS %s: %v\n", posId, err)
			return false
		}

		cleanItemID := strings.TrimPrefix(matchingSpec.ItemId, "kivio-ecommerce∼")
		itemRaw, err := s.ecommerceSvc.GetItemByIDRaw(ctx, cleanItemID, credentials.ApiURL, credentials.ApiKey)
		if err != nil {
			fmt.Printf("Error al obtener datos raw del item %s: %v\n", cleanItemID, err)
			return false
		}

		if itemRaw == nil {
			fmt.Printf("No se encontraron datos raw para el item %s\n", cleanItemID)
			return false
		}

		var extResp struct {
			Products []map[string]interface{} `json:"products"`
		}
		if err := json.Unmarshal(itemRaw, &extResp); err != nil {
			fmt.Printf("Error al parsear respuesta JSON para item %s: %v\n", cleanItemID, err)
			return false
		}

		if len(extResp.Products) == 0 {
			fmt.Printf("No se encontraron productos en la respuesta para item %s\n", cleanItemID)
			return false
		}

		matchingItem := extResp.Products[0]

		switch spec.Parameter {
		case "StockQuantity":
			if stock, ok := matchingItem["stock_quantity"].(float64); ok {
				return verifyNumericValue(stock, spec)
			}
			fmt.Printf("StockQuantity no encontrado o no es float64 para el artículo %s.\n", cleanItemID)
		case "Weight":
			if weight, ok := matchingItem["weight"].(float64); ok {
				return verifyNumericValue(weight, spec)
			}
			fmt.Printf("Weight no encontrado o no es float64 para el artículo %s.\n", cleanItemID)
		case "Price", "OldPrice":
			if price, ok := matchingItem["price"].(float64); ok {
				return verifyNumericValue(price, spec)
			}
			fmt.Printf("Precio no encontrado o no es float64 para el artículo %s.\n", cleanItemID)
		case "Published", "VisibleIndividually", "IsFreeShipping":
			if published, ok := matchingItem["published"].(bool); ok {
				return verifyBooleanValue(published, spec)
			}
			fmt.Printf("%s no encontrado o no es bool para el artículo %s.\n", spec.Parameter, cleanItemID)
		case "AvailableStartDate", "AvailableEndDate":
			var dateStr string
			var ok bool

			if spec.Parameter == "AvailableStartDate" {
				dateStr, ok = matchingItem["available_start_date_time_utc"].(string)
			} else {
				dateStr, ok = matchingItem["available_end_date_time_utc"].(string)
			}

			if ok {
				if !strings.HasSuffix(dateStr, "Z") {
					dateStr += "Z"
				}
				date, err := time.Parse(time.RFC3339, dateStr)
				if err != nil {
					fmt.Printf("Error al parsear la cadena de fecha '%s' (RFC3339) para el artículo %s: %v\n", dateStr, cleanItemID, err)
					return false
				}
				return verifyDateValue(date, spec)
			}
			fmt.Printf("Fecha disponible no encontrada o no es cadena (available_start_date_time_utc o available_end_date_time_utc) para el artículo %s.\n", cleanItemID)
		case "Tags":
			if tags, ok := matchingItem["tags"].([]interface{}); ok {
				tagStr := strings.Join(interfaceSliceToStringSlice(tags), ",")
				return verifyCategoryValue(tagStr, spec)
			}
			fmt.Printf("Tags no encontrados o no son un array de interfaces para el artículo %s.\n", cleanItemID)
		default:
			fmt.Printf("Parámetro desconocido o no manejado '%s' para el artículo %s.\n", spec.Parameter, cleanItemID)
		}
	}

	return false
}

func verifyDateValue(value time.Time, spec ruleSpecDomain.RuleSpecification) bool {
	dateStr := spec.Type
	if idx := strings.Index(dateStr, "("); idx != -1 {
		dateStr = strings.TrimSpace(dateStr[:idx])
	}

	formats := []string{
		time.RFC3339,
		"Mon Jan 02 2006 15:04:05 GMT-0700",
		"Mon Jan 02 15:04:05 MST 2006",
		"2006-01-02",
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
		fmt.Printf("Error al parsear spec.Type '%s' como fecha en verifyDateValue (intentando múltiples formatos): %v\n", dateStr, err)
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
		fmt.Printf("Operador desconocido '%s' para comparación de fechas.\n", spec.Operator)
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
		fmt.Printf("Operador desconocido '%s' para comparación de categorías.\n", spec.Operator)
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
	cleanStr := strings.ReplaceAll(spec.Type, ".", "")
	parameterValue, err := strconv.ParseFloat(cleanStr, 64)
	if err != nil {
		fmt.Printf("Error al parsear spec.Type '%s' como float64 en verifyNumericValue: %v\n", spec.Type, err)
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
		fmt.Printf("Operador desconocido '%s' para comparación numérica.\n", spec.Operator)
		return false
	}
}

func verifyBooleanValue(value bool, spec ruleSpecDomain.RuleSpecification) bool {
	parameterValue, err := strconv.ParseBool(spec.Type)
	if err != nil {
		fmt.Printf("Error al parsear spec.Type '%s' como bool en verifyBooleanValue: %v\n", spec.Type, err)
		return false
	}

	switch spec.Operator {
	case "=":
		return value == parameterValue
	case "!=":
		return value != parameterValue
	default:
		fmt.Printf("Operador desconocido '%s' para comparación booleana.\n", spec.Operator)
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
		time.RFC3339,
		"Mon Jan 02 2006 15:04:05 GMT-0700",
		"Mon Jan 02 15:04:05 MST 2006",
		"2006-01-02",
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
		fmt.Printf("Error al parsear la fecha '%s' de la especificación de la regla (se intentaron múltiples formatos): %v\n", dateStr, err)
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
		fmt.Printf("Operador desconocido '%s' para comparación de fecha actual.\n", spec.Operator)
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

func getRuleIds(rules []domain.Rule) []string {
	ids := make([]string, len(rules))
	for i, rule := range rules {
		ids[i] = rule.RuleId
	}
	return ids
}
