package domain

import (
	"fmt"
	"time"
)

type ItemSpecificationState string

const (
	StateAvailable   ItemSpecificationState = "available"
	StateReserved    ItemSpecificationState = "reserved"
	StateNoAvailable ItemSpecificationState = "noavailable"
)

type ItemSource string

const (
	SourceLocal     ItemSource = "local"
	SourceEcommerce ItemSource = "ecommerce"
)

type ItemSpecification struct {
	Id                 string
	Amount             int64
	Currency           string
	ExpireAt           time.Time
	OfferId            string
	ItemId             string
	Availability       int64
	IsExternal         bool
	Source             ItemSource
	PointOfSaleId      string
	State              ItemSpecificationState
	ReservedAt         *time.Time
	AllowMultipleItems bool
}

func (o *ItemSpecification) Update(currency, offerId, itemId, pointOfSaleId string, amount, availability int64, expireAt time.Time) error {
	if currency == "" {
		return fmt.Errorf("Currency cannot be empty")
	}
	if offerId == "" {
		return fmt.Errorf("offerId cannot be empty")
	}
	if itemId == "" {
		return fmt.Errorf("itemId cannot be empty")
	}
	if pointOfSaleId == "" {
		return fmt.Errorf("pointOfSaleId cannot be empty")
	}
	if amount == 0 {
		return fmt.Errorf("amount cannot be empty")
	}
	if expireAt.String() == "" {
		return fmt.Errorf("expireAt cannot be empty")
	}

	o.Currency = currency
	o.OfferId = offerId
	o.ItemId = itemId
	o.Amount = amount
	o.ExpireAt = expireAt
	o.Availability = availability
	o.PointOfSaleId = pointOfSaleId

	return nil
}

func (o *ItemSpecification) UpdateAllowMultipleItems(allowMultiple bool) {
	o.AllowMultipleItems = allowMultiple
}

func (o *ItemSpecification) UpdateState(state ItemSpecificationState) error {
	if state != StateAvailable && state != StateReserved && state != StateNoAvailable {
		return fmt.Errorf("invalid state: %s. Valid states are: available, reserved, noavailable", state)
	}

	switch o.State {
	case StateAvailable:
		if state != StateReserved {
			return fmt.Errorf("invalid transition from %s to %s. From available, only transition to reserved is allowed", o.State, state)
		}
	case StateReserved:
		if state != StateNoAvailable && state != StateAvailable {
			return fmt.Errorf("invalid transition from %s to %s. From reserved, only transitions to noavailable or available are allowed", o.State, state)
		}
	case StateNoAvailable:
		return fmt.Errorf("invalid transition from %s to %s. No transitions are allowed from noavailable state", o.State, state)
	default:
		return fmt.Errorf("unknown current state: %s", o.State)
	}

	o.State = state

	if state == StateReserved {
		now := time.Now()
		o.ReservedAt = &now
	} else {
		o.ReservedAt = nil
	}

	return nil
}

func (o *ItemSpecification) IsReservationExpired() bool {
	if o.State != StateReserved || o.ReservedAt == nil {
		return false
	}
	return time.Since(*o.ReservedAt) > 20*time.Minute
}

func (o *ItemSpecification) CheckAndUpdateExpiredReservation() error {
	if o.IsReservationExpired() {
		o.State = StateAvailable
		o.ReservedAt = nil
	}
	return nil
}

func (o *ItemSpecification) CheckAndUpdateAvailabilityState() error {
	if o.Availability == 0 && o.State != StateNoAvailable {
		o.State = StateNoAvailable
		o.ReservedAt = nil
	}
	return nil
}

func (o *ItemSpecification) GetSource() ItemSource {
	if o.Source != "" {
		return o.Source
	}

	if o.IsExternal {
		return SourceEcommerce
	}

	return SourceLocal
}

func (o *ItemSpecification) SetSource(source ItemSource) {
	o.Source = source
	o.IsExternal = (source != SourceLocal)
}
