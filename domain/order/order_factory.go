package domain

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

type OrderFactory interface {
	CreateOrder(customerId, externalId, itemSpecificationId, offerId, pointOfSaleId, billingId, extraData string, offeredAmount int64, quantity int) (*Order, error)
}

type DefaultOrderFactory struct{}

// NewOrderFactory creates a new instance of the default order factory
func NewOrderFactory() OrderFactory {
	return &DefaultOrderFactory{}
}

// CreateOrder creates a new order instance with the provided details, validating required fields
func (f *DefaultOrderFactory) CreateOrder(customerId, externalId, itemSpecificationId, offerId, pointOfSaleId, billingId, extraData string, offeredAmount int64, quantity int) (*Order, error) {

	if customerId == "" {
		return nil, fmt.Errorf("CustomerId cannot be empty")
	}
	if externalId == "" {
		return nil, fmt.Errorf("ExternalId cannot be empty")
	}
	if itemSpecificationId == "" {
		return nil, fmt.Errorf("ItemId cannot be empty")
	}
	if extraData == "" {
		return nil, fmt.Errorf("extraData cannot be empty")
	}
	if offeredAmount == 0 {
		return nil, fmt.Errorf("OfferedAmount cannot be empty")
	}
	if pointOfSaleId == "" {
		return nil, fmt.Errorf("PointOfSaleId cannot be empty")
	}
	if billingId == "" {
		return nil, fmt.Errorf("BillingId cannot be empty")
	}
	return &Order{
		OrderId:             generateUUID(),
		OfferId:             offerId,
		OfferedAmount:       offeredAmount,
		CreatedAt:           time.Now(),
		CustomerId:          customerId,
		ExternalId:          externalId,
		BillingId:           billingId,
		ExtraData:           extraData,
		ItemSpecificationId: itemSpecificationId,
		SortKey:             "ACTIVE",
		PointOfSaleId:       pointOfSaleId,
		IsWinner:            false,
		TotalQuantity:       quantity,
	}, nil
}

// generateUUID generates a new UUID string for order identification
func generateUUID() string {
	return uuid.New().String()
}
