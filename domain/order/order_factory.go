package domain

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

type OrderFactory interface {
	CreateOrder(customerId, externalId, itemSpecificationId, offerId string, offeredAmount int64) (*Order, error)
}

type DefaultOrderFactory struct{}

func NewOrderFactory() OrderFactory {
	return &DefaultOrderFactory{}
}

func (f *DefaultOrderFactory) CreateOrder(customerId, externalId, itemSpecificationId, offerId string, offeredAmount int64) (*Order, error) {

	if customerId == "" {
		return nil, fmt.Errorf("CustomerId cannot be empty")
	}
	if externalId == "" {
		return nil, fmt.Errorf("ExternalId cannot be empty")
	}
	if itemSpecificationId == "" {
		return nil, fmt.Errorf("ItemId cannot be empty")
	}
	if offeredAmount == 0 {
		return nil, fmt.Errorf("OfferedAmount cannot be empty")
	}
	return &Order{
		OrderId:             generateUUID(),
		OfferId:             offerId,
		OfferedAmount:       offeredAmount,
		CreatedAt:           time.Now(),
		CustomerId:          customerId,
		ExternalId:          externalId,
		ItemSpecificationId: itemSpecificationId,
		SortKey:             "ACTIVE",
	}, nil
}

func generateUUID() string {
	return uuid.New().String()
}
