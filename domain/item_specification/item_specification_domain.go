package domain

import (
	"fmt"
	"time"
)

type ItemSpecification struct {
	Id            string
	Amount        int64
	Currency      string
	ExpireAt      time.Time
	OfferId       string
	ItemId        string
	Availability  int64
	IsExternal    bool
	PointOfSaleId string
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
	if availability == 0 {
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
