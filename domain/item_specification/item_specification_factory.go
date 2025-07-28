package domain

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

type ItemSpecificationFactory interface {
	CreateItemSpecification(currency, offerId, itemId, pointOfSaleId string, amount, availability int64, expireAt time.Time, isExternal bool) (*ItemSpecification, error)
}

type DefaultItemSpecificationFactory struct{}

func NewItemSpecificationFactory() ItemSpecificationFactory {
	return &DefaultItemSpecificationFactory{}
}

func (f *DefaultItemSpecificationFactory) CreateItemSpecification(currency, offerId, itemId, pointOfSaleId string, amount, availability int64, expireAt time.Time, isExternal bool) (*ItemSpecification, error) {

	if currency == "" {
		return nil, fmt.Errorf("Currency cannot be empty")
	}
	if offerId == "" {
		return nil, fmt.Errorf("OfferId cannot be empty")
	}
	if itemId == "" {
		return nil, fmt.Errorf("ItemId cannot be empty")
	}
	if pointOfSaleId == "" {
		return nil, fmt.Errorf("PointOfSaleId cannot be empty")
	}
	if amount == 0 {
		return nil, fmt.Errorf("amount cannot be empty")
	}
	if availability == 0 {
		return nil, fmt.Errorf("availability cannot be empty")
	}
	if expireAt.String() == "" {
		return nil, fmt.Errorf("expireAt cannot be empty")
	}

	return &ItemSpecification{
		Id:            generateUUID(),
		Amount:        amount,
		Currency:      currency,
		ExpireAt:      expireAt,
		OfferId:       offerId,
		ItemId:        itemId,
		Availability:  availability,
		IsExternal:    isExternal,
		PointOfSaleId: pointOfSaleId,
		State:         StateAvailable,
		ReservedAt:    nil,
	}, nil
}

func generateUUID() string {
	return uuid.New().String()
}
