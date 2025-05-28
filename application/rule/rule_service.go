package services

import (
	"context"
	"fmt"
	"strconv"

	ruleSpecService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/rule_specification"
	ruleDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/rule"
	ruleSpecificationDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/rule_specification"
	infrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/rule"
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
	GetRuleData(pointOfSaleId string) (map[string]interface{}, error)
}

type ruleService struct {
	repo                      infrastructure.RuleRepository
	RuleFactory               ruleDomain.RuleFactory
	ruleSpecificationService  ruleSpecService.RuleSpecificationService
	suggestRuleColumnsService SuggestRuleColumnsService
}

func NewRuleService(
	repo infrastructure.RuleRepository,
	ruleFactory ruleDomain.RuleFactory,
	ruleSpecificationService ruleSpecService.RuleSpecificationService,
	suggestRuleColumnsService SuggestRuleColumnsService,
) RuleService {
	return &ruleService{
		repo:                      repo,
		RuleFactory:               ruleFactory,
		ruleSpecificationService:  ruleSpecificationService,
		suggestRuleColumnsService: suggestRuleColumnsService,
	}
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
	if err := s.repo.DeleteRule(ctx, id); err != nil {
		return fmt.Errorf("failed to delete rule with ID %s: %w", id, err)
	}

	if err := s.ruleSpecificationService.DeleteRuleSpecByRuleId(ctx, id); err != nil {
		return fmt.Errorf("failed to delete rule specifications for rule ID %s: %w", id, err)
	}

	return nil
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

func (s *ruleService) GetRuleData(pointOfSaleId string) (map[string]interface{}, error) {
	return s.suggestRuleColumnsService.Execute(pointOfSaleId)
}
