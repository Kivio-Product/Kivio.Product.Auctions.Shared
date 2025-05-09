package services

import (
	"context"
	"strconv"

	ruleDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/rule"
	ruleSpecificationDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/rule_specification"
	sheetsDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/sheets"
	infrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/rule"
	"github.com/aws/aws-sdk-go/service/dynamodb"
)

type RuleService interface {
	GenerateRule(ctx context.Context, externalId, itemId, offerId, posId string) (*ruleDomain.Rule, error)
	UpdateRule(ctx context.Context, ruleId, externalId, itemId, offerId string) error
	UpdateRuleState(ctx context.Context, ruleId, state string) error
	GetRuleById(ctx context.Context, id string) (*ruleDomain.Rule, error)
	DeleteRuleById(ctx context.Context, id string) error
	GetRulesByOfferId(ctx context.Context, id string) ([]ruleDomain.Rule, error)
	GetRulesByPosId(ctx context.Context, id, limit string, lastEvaluatedKey map[string]*dynamodb.AttributeValue) ([]ruleDomain.Rule, map[string]*dynamodb.AttributeValue, error)
	GetRules() ([]ruleDomain.Rule, error)
	GetRulesSpecificationByRuleId(ctx context.Context, ruleIds string) ([]ruleSpecificationDomain.RuleSpecification, error)
	GetCategorizedRules(fields []sheetsDomain.RuleField) map[string][]sheetsDomain.RuleField
}
type ruleService struct {
	repo        infrastructure.RuleRepository
	RuleFactory ruleDomain.RuleFactory
}

func NewRuleService(repo infrastructure.RuleRepository, ruleFactory ruleDomain.RuleFactory) RuleService {
	return &ruleService{repo: repo, RuleFactory: ruleFactory}
}

type Response[T any] struct {
	Data   T        `json:"data,omitempty"`
	Errors []string `json:"errors,omitempty"`
}

type GetStateResponse struct {
	State string `json:"state"`
}

type GenerateTokenResponse struct {
	Token string `json:"token"`
}

type UpdateOfferStateRequest struct {
	OfferId string `json:"offerId"`
	State   string `json:"state"`
}

func (s *ruleService) GenerateRule(ctx context.Context, externalId, itemId, offerId, posId string) (*ruleDomain.Rule, error) {
	rules, err := s.RuleFactory.CreateRule(offerId, externalId, itemId, posId)
	if err != nil {
		return &ruleDomain.Rule{}, err
	}
	rules = ruleDomain.GenerateCreatedState(rules)
	if err := s.repo.SaveRule(ctx, rules); err != nil {
		return &ruleDomain.Rule{}, err
	}
	return rules, nil
}

func (s *ruleService) UpdateRule(ctx context.Context, ruleId, externalId, itemId, offerId string) error {
	rule, err := s.repo.GetRuleById(ctx, ruleId)
	if err != nil {
		return err
	}
	err = rule.Update(externalId, itemId, offerId)
	if err != nil {
		return err
	}
	return s.repo.SaveRule(ctx, rule)
}

func (s *ruleService) DeleteRuleById(ctx context.Context, id string) error {
	err := s.repo.DeleteRule(ctx, id)
	return err
}

func (s *ruleService) GetRuleById(ctx context.Context, id string) (*ruleDomain.Rule, error) {
	items, err := s.repo.GetRuleById(ctx, id)
	if err != nil {
		return &ruleDomain.Rule{}, err
	}
	return items, nil
}

func (s *ruleService) GetRulesByOfferId(ctx context.Context, id string) ([]ruleDomain.Rule, error) {
	items, err := s.repo.GetOfferRules(id)
	if err != nil {
		return nil, err
	}
	return items, nil
}

func (s *ruleService) GetRulesByPosId(ctx context.Context, id, limit string, lastEvaluatedKey map[string]*dynamodb.AttributeValue) ([]ruleDomain.Rule, map[string]*dynamodb.AttributeValue, error) {

	limitInt, err := strconv.Atoi(limit)
	if err != nil {
		return nil, nil, err
	}

	items, lastKey, err := s.repo.GetRulesByPosIdPaged(ctx, id, limitInt, lastEvaluatedKey)
	if err != nil {
		return nil, nil, err
	}
	return items, lastKey, nil
}

func (s *ruleService) GetRules() ([]ruleDomain.Rule, error) {
	rules, err := s.repo.GetAllRules()
	if err != nil {
		return nil, err
	}
	return rules, nil
}

func (s *ruleService) GetRulesSpecificationByRuleId(ctx context.Context, ruleId string) ([]ruleSpecificationDomain.RuleSpecification, error) {
	items, err := s.repo.GetRulesSpecification(ruleId)
	if err != nil {
		return nil, err
	}
	return items, nil
}

func (s *ruleService) UpdateRuleState(ctx context.Context, ruleId, state string) error {
	rule, err := s.repo.GetRuleById(ctx, ruleId)
	err = rule.UpdateState(state)
	if err != nil {
		return err
	}
	return s.repo.SaveRule(ctx, rule)
}

func (s *ruleService) GetCategorizedRules(fields []sheetsDomain.RuleField) map[string][]sheetsDomain.RuleField {
	categorizedRules := make(map[string][]sheetsDomain.RuleField)

	var localRules []sheetsDomain.RuleField
	var otherRules []sheetsDomain.RuleField

	var dateExists, availabilityExists bool

	for _, field := range fields {
		switch field.Field {
		case "date":
			dateExists = true
			localRules = append(localRules, field)
		case "availability":
			availabilityExists = true
			localRules = append(localRules, field)
		default:
			otherRules = append(otherRules, field)
		}
	}

	if !dateExists {
		dateOperators := []string{"=", ">", "<", ">=", "<=", "!="}
		localRules = append(localRules, sheetsDomain.RuleField{
			Field:         "date",
			ParameterType: "numérico",
			Operators:     dateOperators,
		})
	}

	if !availabilityExists {
		availabilityOperators := []string{"=", ">", "<", ">=", "<=", "!="}
		localRules = append(localRules, sheetsDomain.RuleField{
			Field:         "availability",
			ParameterType: "numérico",
			Operators:     availabilityOperators,
		})
	}

	categorizedRules["local"] = localRules

	if len(otherRules) > 0 {
		categorizedRules["google sheets"] = otherRules
	}

	return categorizedRules
}
