package services

import (
	"context"
	"fmt"

	services "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/ecommerce"
	sheetService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/sheets"
	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/repository"
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

	sheetData, err := s.sheetService.FetchSheetData(pointOfSaleId)
	if err != nil {
		return nil, fmt.Errorf("error fetching sheet data: %w", err)
	}

	credentials, err := s.ecommerceCredentialsSvc.GetCredentials(ctx, pointOfSaleId)
	if err != nil {
		return nil, fmt.Errorf("error fetching ecommerce credentials: %w", err)
	}

	ecommerceResponse, err := s.ecommerceService.GetItemsRaw(credentials.Context, credentials.ApiURL, credentials.ApiKey)
	if err != nil {
		return nil, fmt.Errorf("error fetching ecommerce items: %w", err)
	}

	if len(sheetData.Values) < 2 && len(ecommerceResponse) == 0 {
		return nil, fmt.Errorf("insufficient data in both sheet and ecommerce")
	}

	headers := sheetData.Values[0]

	suggestions, err := s.suggestionCache.GetCachedSuggestions(ctx, pointOfSaleId, headers)
	if err != nil {
		suggestions, err = s.ruleSuggester.SuggestRules(sheetData, ecommerceResponse)
		if err != nil {
			return nil, fmt.Errorf("error generating suggestions: %w", err)
		}

		if err := s.suggestionCache.CacheSuggestions(ctx, pointOfSaleId, headers, suggestions); err != nil {
			return nil, fmt.Errorf("error caching suggestions: %w", err)
		}
	}

	return map[string]interface{}{
		"categories": suggestions,
	}, nil
}
