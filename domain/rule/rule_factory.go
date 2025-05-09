package domain

import (
	"fmt"

	"github.com/google/uuid"
)

type RuleFactory interface {
	CreateRule(offerId, externalId, itemId, posId string) (*Rule, error)
}

type DefaultRuleFactory struct{}

func NewRuleFactory() RuleFactory {
	return &DefaultRuleFactory{}
}

func (f *DefaultRuleFactory) CreateRule(offerId, externalId, itemSpecificationId, posId string) (*Rule, error) {
	if offerId == "" {
		return nil, fmt.Errorf("OfferId cannot be empty")
	}
	if externalId == "" {
		return nil, fmt.Errorf("ExternalId cannot be empty")
	}
	if itemSpecificationId == "" {
		return nil, fmt.Errorf("ItemId cannot be empty")
	}
	if posId == "" {
		return nil, fmt.Errorf("PosId cannot be empty")
	}
	return &Rule{
		RuleId:              generateUUID(),
		ExternalId:          externalId,
		ItemSpecificationId: itemSpecificationId,
		OfferId:             offerId,
		PosId:               posId,
	}, nil
}

func generateUUID() string {
	return uuid.New().String()
}
