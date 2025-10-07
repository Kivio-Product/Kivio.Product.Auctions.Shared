package domain

import (
	"fmt"

	"github.com/google/uuid"
)

type RuleSpecificationFactory interface {
	CreateRuleSpecification(ruleId, typer, operator, parameter, offerId, itemName string) (*RuleSpecification, error)
}

type DefaultRuleSpecificationFactory struct{}

func NewRuleSpecificationFactory() RuleSpecificationFactory {
	return &DefaultRuleSpecificationFactory{}
}

func (f *DefaultRuleSpecificationFactory) CreateRuleSpecification(ruleId, typer, operator, parameter, offerId, itemName string) (*RuleSpecification, error) {
	if ruleId == "" {
		return nil, fmt.Errorf("RuleId cannot be empty")
	}
	if typer == "" {
		return nil, fmt.Errorf("Type cannot be empty")
	}
	if operator == "" {
		return nil, fmt.Errorf("Operator cannot be empty")
	}
	if parameter == "" {
		return nil, fmt.Errorf("Parameter cannot be empty")
	}
	if offerId == "" {
		return nil, fmt.Errorf("offerId cannot be empty")
	}
	return &RuleSpecification{
		RuleSpecificationId: generateUUID(),
		RuleId:              ruleId,
		Type:                typer,
		Operator:            operator,
		Parameter:           parameter,
		OfferId:             offerId,
		ItemName:            itemName,
	}, nil
}

func generateUUID() string {
	return uuid.New().String()
}
