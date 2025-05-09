package domain

import "errors"

type Rule struct {
	RuleId              string
	ExternalId          string
	ItemSpecificationId string
	OfferId             string
	State               string
	PosId               string
}

var (
	StateCreated  = "Created"
	StateActive   = "Active"
	StateInactive = "Inactive"
)

func GenerateCreatedState(rule *Rule) *Rule {
	rule.State = StateCreated
	return rule
}

func (o *Rule) Update(externalId, itemSpecificationId, offerId string) error {
	if externalId == "" {
		return errors.New("El externalId no puede estar vacío")
	}
	if itemSpecificationId == "" {
		return errors.New("La itemId no puede estar vacía")
	}
	if offerId == "" {
		return errors.New("La offerId no puede estar vacía")
	}
	o.ExternalId = externalId
	o.ItemSpecificationId = itemSpecificationId
	o.OfferId = offerId
	return nil
}

func (o *Rule) UpdateState(state string) error {
	if state == "" {
		return errors.New("El estado no puede estar vacío")
	}
	o.State = state
	return nil
}
