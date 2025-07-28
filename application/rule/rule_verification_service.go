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
	offerService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/offer"
	itemSpecificationDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item_specification"
	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/rule"
	ruleSpecDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/rule_specification"
	offerClient "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/api/offer"
	offerInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/offer"
	infrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/rule"
)

type RuleVerificationService interface {
	VerifyRules(ctx context.Context, pointOfSaleId string) error
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
	rules, err := s.ruleRepo.GetOfferRules(offerId)
	if err != nil {
		return false, fmt.Errorf("fallo al obtener reglas para la oferta %s: %w", offerId, err)
	}

	var (
		wg            sync.WaitGroup
		hasActiveRule bool
	)

	var ecommerceItems map[string]interface{}
	if len(rules) > 0 {
		credentials, err := s.ecommerceCredSvc.GetCredentials(ctx, rules[0].PosId)
		if err != nil {
			fmt.Printf("Advertencia: Error al obtener credenciales de e-commerce para POS %s: %v\n", rules[0].PosId, err)
		} else {
			rawData, err := s.ecommerceSvc.GetAllItemsRaw(ctx, credentials.ApiURL, credentials.ApiKey)
			if err != nil {
				fmt.Printf("Advertencia: Error al obtener datos de e-commerce para POS %s: %v\n", rules[0].PosId, err)
			} else {
				if err := json.Unmarshal(rawData, &ecommerceItems); err != nil {
					fmt.Printf("Advertencia: Error al parsear datos de e-commerce para POS %s: %v\n", rules[0].PosId, err)
				}
			}
		}
	}

	semaphore := make(chan struct{}, 5)

	for i := range rules {
		wg.Add(1)
		go func(rule *domain.Rule) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if err := s.processRule(ctx, rule, &hasActiveRule, ecommerceItems); err != nil {
				fmt.Printf("Error al procesar la regla %s para la oferta %s: %v\n", rule.RuleId, offerId, err)
			}
		}(&rules[i])
	}

	wg.Wait()
	return hasActiveRule, nil
}

func (s *ruleVerificationService) processRule(ctx context.Context, rule *domain.Rule, hasActiveRule *bool, ecommerceItems map[string]interface{}) error {
	var mu sync.Mutex
	specifications, err := s.ruleRepo.GetRulesSpecification(rule.RuleId)
	if err != nil {
		return fmt.Errorf("fallo al obtener especificaciones para la regla %s: %w", rule.RuleId, err)
	}

	itemSpecs, err := s.itemSpecSvc.GetItemSpecByOfferId(ctx, rule.OfferId, rule.PosId)
	if err != nil {
		return fmt.Errorf("fallo al obtener especificaciones de artículo para la oferta %s y POS %s: %w", rule.OfferId, rule.PosId, err)
	}

	isActive := s.evaluateRuleSpecifications(specifications, itemSpecs, rule.ItemSpecificationId, ecommerceItems)
	rule.State = getRuleState(isActive)

	if err := s.ruleRepo.SaveRule(ctx, rule); err != nil {
		return fmt.Errorf("fallo al guardar el estado para la regla %s: %w", rule.RuleId, err)
	}

	if isActive {
		mu.Lock()
		*hasActiveRule = true
		mu.Unlock()
	}

	return nil
}

func (s *ruleVerificationService) evaluateRuleSpecifications(
	specifications []ruleSpecDomain.RuleSpecification,
	itemSpecs []itemSpecificationDomain.ItemSpecification,
	itemSpecId string,
	ecommerceItems map[string]interface{},
) bool {
	for _, spec := range specifications {
		if spec.Parameter == "offerType" {
			continue
		}
		if s.verifySpecification(spec, itemSpecs, itemSpecId, ecommerceItems) {
			return true
		}
	}
	return false
}

func (s *ruleVerificationService) verifySpecification(
	spec ruleSpecDomain.RuleSpecification,
	itemSpecs []itemSpecificationDomain.ItemSpecification,
	itemSpecId string,
	ecommerceItems map[string]interface{},
) bool {
	var matchingSpec *itemSpecificationDomain.ItemSpecification
	for _, itemSpec := range itemSpecs {
		if itemSpec.Id == itemSpecId {
			matchingSpec = &itemSpec
			break
		}
	}

	switch spec.Parameter {
	case "current date":
		return verifyDateSpecification(spec)
	case "availability":
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

	itemId := strings.TrimPrefix(matchingSpec.ItemId, "kivio-ecommerce∼")
	itemIdInt, err := strconv.Atoi(itemId)
	if err != nil {
		fmt.Printf("Error al convertir itemId '%s' a int: %v\n", itemId, err)
		return false
	}

	products, ok := ecommerceItems["products"].([]interface{})
	if !ok {
		fmt.Printf("Los datos de e-commerce no contienen un array 'products' o no están en el formato esperado.\n")
		return false
	}

	var matchingItem map[string]interface{}
	for _, product := range products {
		if productMap, ok := product.(map[string]interface{}); ok {
			if id, ok := productMap["id"].(float64); ok && int(id) == itemIdInt {
				matchingItem = productMap
				break
			}
		}
	}

	if matchingItem == nil {
		fmt.Printf("No se encontró artículo de e-commerce coincidente para el ID: %d (original: %s). Eliminando especificación del artículo.\n", itemIdInt, matchingSpec.ItemId)
		if err := s.itemSpecSvc.Delete(context.Background(), matchingSpec.Id); err != nil {
			fmt.Printf("Error al eliminar la especificación del artículo %s: %v\n", matchingSpec.Id, err)
		} else {
			fmt.Printf("Especificación del artículo %s eliminada exitosamente.\n", matchingSpec.Id)
		}
		return false
	}

	switch spec.Parameter {
	case "StockQuantity":
		if stock, ok := matchingItem["stock_quantity"].(float64); ok {
			return verifyNumericValue(stock, spec)
		}
		fmt.Printf("StockQuantity no encontrado o no es float64 para el artículo %d.\n", itemIdInt)
	case "Price", "OldPrice":
		if price, ok := matchingItem["price"].(float64); ok {
			return verifyNumericValue(price, spec)
		}
		fmt.Printf("Precio no encontrado o no es float64 para el artículo %d.\n", itemIdInt)
	case "Published", "VisibleIndividually", "IsFreeShipping":
		if published, ok := matchingItem["published"].(bool); ok {
			return verifyBooleanValue(published, spec)
		}
		fmt.Printf("%s no encontrado o no es bool para el artículo %d.\n", spec.Parameter, itemIdInt)
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
				fmt.Printf("Error al parsear la cadena de fecha '%s' (RFC3339) para el artículo %d: %v\n", dateStr, itemIdInt, err)
				return false
			}
			return verifyDateValue(date, spec)
		}
		fmt.Printf("Fecha disponible no encontrada o no es cadena (available_start_date_time_utc o available_end_date_time_utc) para el artículo %d.\n", itemIdInt)
	case "Tags":
		if tags, ok := matchingItem["tags"].([]interface{}); ok {
			tagStr := strings.Join(interfaceSliceToStringSlice(tags), ",")
			return verifyCategoryValue(tagStr, spec)
		}
		fmt.Printf("Tags no encontrados o no son un array de interfaces para el artículo %d.\n", itemIdInt)
	default:
		fmt.Printf("Parámetro desconocido o no manejado '%s' para el artículo %d.\n", spec.Parameter, itemIdInt)
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
