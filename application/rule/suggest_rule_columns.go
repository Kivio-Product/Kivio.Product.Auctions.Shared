package services

import (
	"context"
	"fmt"

	sheetService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/sheets"
	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/repository"
	"github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/ai/google_studio"
)

type SuggestRuleColumnsService interface {
	Execute(pointOfSaleId string) (map[string]interface{}, error)
}

type suggestRuleColumnsService struct {
	sheetService  sheetService.SheetService
	ruleService   RuleService
	ruleSuggester domain.RuleSuggestionAI
}

func NewSuggestRuleColumnsService(
	sheetService sheetService.SheetService,
	ruleService RuleService,
) SuggestRuleColumnsService {
	return &suggestRuleColumnsService{
		sheetService:  sheetService,
		ruleService:   ruleService,
		ruleSuggester: google_studio.NewGoogleStudioRuleSuggester(),
	}
}

func (s *suggestRuleColumnsService) Execute(pointOfSaleId string) (map[string]interface{}, error) {
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

	rules, err := s.ruleService.GetRules()
	if err != nil {
		return nil, fmt.Errorf("error getting rules: %w", err)
	}

	var allRuleSpecs []interface{}
	for _, rule := range rules {
		ruleSpecs, err := s.ruleService.GetRulesSpecificationByRuleId(context.Background(), rule.RuleId)
		if err != nil {
			return nil, fmt.Errorf("error getting rule specifications for rule ID %v: %w", rule.RuleId, err)
		}
		allRuleSpecs = append(allRuleSpecs, ruleSpecs)
	}

	return map[string]interface{}{
		"sheetData":          sheetData,
		"suggestedRules":     suggestedRules,
		"rules":              rules,
		"ruleSpecifications": allRuleSpecs,
	}, nil
}
