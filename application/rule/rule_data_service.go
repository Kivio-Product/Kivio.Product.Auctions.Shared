package services

import (
	"fmt"

	sheetService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/sheets"
	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/repository"
	infrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/rule"
)

type RuleDataService interface {
	GetRuleData(pointOfSaleId string) (map[string]interface{}, error)
}

type ruleDataService struct {
	sheetService  sheetService.SheetService
	ruleRepo      infrastructure.RuleRepository
	ruleSuggester domain.RuleSuggestionAI
}

func NewRuleDataService(
	sheetService sheetService.SheetService,
	ruleRepo infrastructure.RuleRepository,
	ruleSuggester domain.RuleSuggestionAI,
) RuleDataService {
	return &ruleDataService{
		sheetService:  sheetService,
		ruleRepo:      ruleRepo,
		ruleSuggester: ruleSuggester,
	}
}

func (s *ruleDataService) GetRuleData(pointOfSaleId string) (map[string]interface{}, error) {
	if pointOfSaleId == "" {
		return nil, fmt.Errorf("pointOfSaleId is required")
	}

	sheetData, err := s.sheetService.FetchSheetData(pointOfSaleId)
	if err != nil {
		return nil, fmt.Errorf("error fetching sheet data: %w", err)
	}

	suggestedRules, err := s.ruleSuggester.SuggestRules(sheetData)
	if err != nil {
		return nil, fmt.Errorf("error getting rule suggestions: %w", err)
	}

	return map[string]interface{}{
		"suggestedRules": suggestedRules,
	}, nil
}
