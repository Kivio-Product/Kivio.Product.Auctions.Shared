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

	// Get sheet data
	sheetData, err := s.sheetService.FetchSheetData(pointOfSaleId)
	if err != nil {
		return nil, fmt.Errorf("error fetching sheet data: %w", err)
	}

	// Get rule suggestions using AI
	suggestedRules, err := s.ruleSuggester.SuggestRules(sheetData)
	if err != nil {
		return nil, fmt.Errorf("error getting rule suggestions: %w", err)
	}

	// Get existing rules
	rules, err := s.ruleRepo.GetAllRules()
	if err != nil {
		return nil, fmt.Errorf("error getting rules: %w", err)
	}

	// Get rule specifications for each rule
	var allRuleSpecs []interface{}
	for _, rule := range rules {
		ruleSpecs, err := s.ruleRepo.GetRulesSpecification(rule.RuleId)
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
