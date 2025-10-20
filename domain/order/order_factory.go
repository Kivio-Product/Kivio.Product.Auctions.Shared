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
// 
// This constructor initializes the default order factory implementation.
// It provides a concrete implementation of the OrderFactory interface for creating
// new order entities with proper validation and initialization.
//
// Returns:
//   - OrderFactory: Configured factory instance ready for order creation
//
// Side Effects:
//   - None (pure constructor)
//
// Technical Details:
//   - Returns DefaultOrderFactory instance
//   - Implements OrderFactory interface
//   - Enables dependency injection pattern
func NewOrderFactory() OrderFactory {
	return &DefaultOrderFactory{}
}

// CreateOrder creates a new order instance with the provided details, validating required fields
// 
// This method creates a new order entity with comprehensive validation of all
// required fields. It generates a unique identifier, sets the creation timestamp,
// and ensures all mandatory information is present before entity creation.
//
// Parameters:
//   - customerId: Unique identifier of the customer placing the order
//   - externalId: External system identifier for the order
//   - itemSpecificationId: Unique identifier of the item specification
//   - offerId: Unique identifier of the offer this order belongs to
//   - pointOfSaleId: Unique identifier of the point of sale
//   - billingId: Unique identifier of the billing record
//   - extraData: Additional data associated with the order
//   - offeredAmount: Monetary amount offered for the order
//   - quantity: Number of items in the order
//
// Returns:
//   - *Order: New order instance with generated ID and timestamp
//   - error: Returns error if validation fails for any required field
//
// Side Effects:
//   - Generates new UUID for order identification
//   - Sets creation timestamp to current time
//
// Technical Details:
//   - Validates all parameters are non-empty/non-zero
//   - Generates UUID using google/uuid package
//   - Sets CreatedAt field to time.Now()
//   - Sets SortKey to "ACTIVE" for active orders
//   - Sets IsWinner to false by default
//   - Sets TotalQuantity to provided quantity
//   - Returns specific error messages for each validation failure
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

// generateUUID creates a new unique identifier string using Google's UUID library
// 
// This helper function encapsulates the UUID generation logic, providing a clean
// abstraction for creating unique identifiers. It uses the google/uuid package
// to generate RFC 4122 compliant UUIDs that are guaranteed to be unique.
//
// Returns:
//   - string: A new UUID in string format (e.g., "550e8400-e29b-41d4-a716-446655440000")
//
// Side Effects:
//   - None (pure function)
//
// Technical Details:
//   - Uses google/uuid.New().String() for UUID generation
//   - Generates version 4 (random) UUIDs
//   - Returns string representation suitable for database storage
func generateUUID() string {
	return uuid.New().String()
}
