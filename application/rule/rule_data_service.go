package services

import (
	"context"
	"fmt"

	services "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/ecommerce"
	sheetService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/sheets"
	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/repository"
	sheetsDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/sheets"
	integrationInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/integration"
	infrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/rule"
)

type RuleDataService interface {
	GetRuleData(ctx context.Context, pointOfSaleId string) (map[string]interface{}, error)
}

type ruleDataService struct {
	sheetService            sheetService.SheetService
	ruleRepo                infrastructure.RuleRepository
	ruleSuggester           domain.RuleSuggestionAI
	suggestionCache         RuleSuggestionCache
	integrationRepository   integrationInfrastructure.IntegrationRepository
	ecommerceService        services.EcommerceService
	ecommerceCredentialsSvc services.EcommerceCredentialsService
}

func NewRuleDataService(
	sheetService sheetService.SheetService,
	ruleRepo infrastructure.RuleRepository,
	ruleSuggester domain.RuleSuggestionAI,
	suggestionCache RuleSuggestionCache,
	integrationRepository integrationInfrastructure.IntegrationRepository,
	ecommerceService services.EcommerceService,
	ecommerceCredentialsSvc services.EcommerceCredentialsService,
) RuleDataService {
	return &ruleDataService{
		sheetService:            sheetService,
		ruleRepo:                ruleRepo,
		ruleSuggester:           ruleSuggester,
		suggestionCache:         suggestionCache,
		integrationRepository:   integrationRepository,
		ecommerceService:        ecommerceService,
		ecommerceCredentialsSvc: ecommerceCredentialsSvc,
	}
}

func (s *ruleDataService) GetRuleData(ctx context.Context, pointOfSaleId string) (map[string]interface{}, error) {
	if pointOfSaleId == "" {
		return nil, fmt.Errorf("pointOfSaleId is required")
	}

	categorizedRules := make(map[string][]sheetsDomain.RuleField)
	dateRule := sheetsDomain.RuleField{
		Field:         "current date",
		ParameterType: "fecha",
		Operators:     []string{"=", "!=", ">", "<", ">=", "<="},
	}
	availabilityRule := sheetsDomain.RuleField{
		Field:         "availability",
		ParameterType: "numérico",
		Operators:     []string{"=", "!=", ">", "<", ">=", "<="},
	}
	categorizedRules["local"] = []sheetsDomain.RuleField{dateRule, availabilityRule}

	sheetData, err := s.sheetService.FetchSheetData(pointOfSaleId)
	if err == nil && len(sheetData.Values) >= 2 {
		emptyEcommerceResponse := []byte("{}")
		suggestions, err := s.ruleSuggester.SuggestRules(sheetData, emptyEcommerceResponse)
		if err == nil {
			if sheetRules, ok := suggestions["google sheets"]; ok && len(sheetRules) > 0 {
				categorizedRules["google sheets"] = sheetRules
			}
		}
	}

	credentials, err := s.ecommerceCredentialsSvc.GetCredentials(ctx, pointOfSaleId)
	if err == nil {
		ecommerceResponse, err := s.ecommerceService.GetItemsRaw(credentials.Context, credentials.ApiURL, credentials.ApiKey, 1, 1)
		if err == nil && len(ecommerceResponse) > 0 {
			emptySheetData := sheetsDomain.SheetData{Values: [][]interface{}{}}
			suggestions, err := s.ruleSuggester.SuggestRules(emptySheetData, ecommerceResponse)
			if err == nil {
				if ecommerceRules, ok := suggestions["kivio_ecommerce"]; ok && len(ecommerceRules) > 0 {
					categorizedRules["kivio_ecommerce"] = ecommerceRules
				}
			}
		}
	}

	if len(sheetData.Values) > 0 {
		if err := s.suggestionCache.CacheSuggestions(ctx, pointOfSaleId, sheetData.Values[0], categorizedRules); err != nil {
			fmt.Printf("Error caching suggestions: %v\n", err)
		}
	}

	return map[string]interface{}{
		"categories": categorizedRules,
	}, nil
}
