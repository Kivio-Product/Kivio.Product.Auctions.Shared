package services

import (
	"context"
	"fmt"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/rule_specification"
	infrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/rule_specification"
)

type RuleSpecificationService interface {
	GenerateRuleSpecification(ctx context.Context, ruleId, typer, operator, parameter, offerId string) (*domain.RuleSpecification, error)
	GetRuleSpecificationById(ctx context.Context, id string) (*domain.RuleSpecification, error)
	GetRuleSpecificationByOfferId(ctx context.Context, offerId string) ([]domain.RuleSpecification, error)
	DeleteRuleSpecificationById(ctx context.Context, id string) error
	GetRuleSpecificationByRuleId(ctx context.Context, id string) ([]domain.RuleSpecification, error)
	UpdateRuleSpecification(ctx context.Context, ruleSpecificationId, typer, operator, parameter string) error
	DeleteRuleSpecByRuleId(ctx context.Context, ruleId string) error
	HasRuleSpecificationByOfferId(ctx context.Context, offerId string) (bool, error)
}

type ruleSpecificationService struct {
	repo                     infrastructure.RuleSpecificationRepository
	RuleSpecificationFactory domain.RuleSpecificationFactory
}

func NewRuleSpecificationService(repo infrastructure.RuleSpecificationRepository, ruleSpecificationFactory domain.RuleSpecificationFactory) RuleSpecificationService {
	return &ruleSpecificationService{repo: repo, RuleSpecificationFactory: ruleSpecificationFactory}
}

func (s *ruleSpecificationService) GenerateRuleSpecification(ctx context.Context, ruleId, typer, operator, parameter, offerId string) (*domain.RuleSpecification, error) {
	ruleSpec, err := s.RuleSpecificationFactory.CreateRuleSpecification(ruleId, typer, operator, parameter, offerId)
	if err != nil {
		return &domain.RuleSpecification{}, err
	}
	ruleSpec = domain.GenerateInactiveState(ruleSpec)
	if err := s.repo.SaveRuleSpecification(ctx, ruleSpec); err != nil {
		return &domain.RuleSpecification{}, err
	}
	return ruleSpec, nil
}

func (s *ruleSpecificationService) DeleteRuleSpecificationById(ctx context.Context, id string) error {
	err := s.repo.DeleteRuleSpecification(ctx, id)
	return err
}

func (s *ruleSpecificationService) GetRuleSpecificationById(ctx context.Context, id string) (*domain.RuleSpecification, error) {
	items, err := s.repo.GetRuleSpecificationById(ctx, id)
	if err != nil {
		return &domain.RuleSpecification{}, err
	}
	return items, nil
}

func (s *ruleSpecificationService) GetRuleSpecificationByOfferId(ctx context.Context, offerId string) ([]domain.RuleSpecification, error) {
	specs, err := s.repo.GetRuleSpecificationByOfferId(ctx, offerId)
	if err != nil {
		return nil, err
	}
	return specs, nil
}

func (s *ruleSpecificationService) UpdateRuleSpecification(ctx context.Context, ruleSpecificationId, typer, operator, parameter string) error {
	rules, err := s.repo.GetRuleSpecificationById(ctx, ruleSpecificationId)
	if err != nil {
		return err
	}
	err = rules.Update(typer, operator, parameter)
	if err != nil {
		return err
	}
	return s.repo.SaveRuleSpecification(ctx, rules)
}

func (s *ruleSpecificationService) GetRuleSpecificationByRuleId(ctx context.Context, id string) ([]domain.RuleSpecification, error) {
	items, err := s.repo.GetRuleSpecificationsByRuleId(id)
	if err != nil {
		return nil, err
	}
	return items, nil
}

func (s *ruleSpecificationService) HasRuleSpecificationByOfferId(ctx context.Context, offerId string) (bool, error) {
	result, err := s.repo.HasRuleSpecificationsForOffer(ctx, offerId)
	if err != nil {
		return false, err
	}
	return result, nil
}

func (s *ruleSpecificationService) DeleteRuleSpecByRuleId(ctx context.Context, ruleId string) error {
	specs, err := s.GetRuleSpecificationByRuleId(ctx, ruleId)
	if err != nil {
		return fmt.Errorf("failed to get rule specifications for rule ID %s: %w", ruleId, err)
	}

	if len(specs) == 0 {
		return fmt.Errorf("no rule specifications found for rule ID %s", ruleId)
	}

	for _, spec := range specs {
		err = s.repo.DeleteRuleSpecification(ctx, spec.RuleSpecificationId)
		if err != nil {
			return fmt.Errorf("failed to delete rule specification %s: %w", spec.RuleSpecificationId, err)
		}
	}

	return nil
}
