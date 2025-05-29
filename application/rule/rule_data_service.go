package services

import (
	"context"
	"fmt"

	sheetService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/sheets"
	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/repository"
	infrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/rule"
)

type RuleDataService interface {
	GetRuleData(ctx context.Context, pointOfSaleId string) (map[string]interface{}, error)
}

type ruleDataService struct {
	sheetService    sheetService.SheetService
	ruleRepo        infrastructure.RuleRepository
	ruleSuggester   domain.RuleSuggestionAI
	suggestionCache RuleSuggestionCache
}

func NewRuleDataService(
	sheetService sheetService.SheetService,
	ruleRepo infrastructure.RuleRepository,
	ruleSuggester domain.RuleSuggestionAI,
	suggestionCache RuleSuggestionCache,
) RuleDataService {
	return &ruleDataService{
		sheetService:    sheetService,
		ruleRepo:        ruleRepo,
		ruleSuggester:   ruleSuggester,
		suggestionCache: suggestionCache,
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

	if len(sheetData.Values) < 2 {
		return nil, fmt.Errorf("insufficient data in sheet")
	}

	headers := sheetData.Values[0]

	// Try to get cached suggestions first
	suggestions, err := s.suggestionCache.GetCachedSuggestions(ctx, pointOfSaleId, headers)
	if err != nil {
		// If cache miss or headers changed, generate new suggestions
		suggestions, err = s.ruleSuggester.SuggestRules(sheetData)
		if err != nil {
			return nil, fmt.Errorf("error generating suggestions: %w", err)
		}

		// Cache the new suggestions
		if err := s.suggestionCache.CacheSuggestions(ctx, pointOfSaleId, headers, suggestions); err != nil {
			return nil, fmt.Errorf("error caching suggestions: %w", err)
		}
	}

	return map[string]interface{}{
		"suggestedRules": suggestions,
	}, nil
}
