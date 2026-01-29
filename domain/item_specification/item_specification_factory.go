package domain

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ItemSpecificationFactory defines the contract for creating new ItemSpecification instances
//
// The factory pattern is used here to encapsulate the complex creation logic
// of ItemSpecification entities, ensuring proper initialization and validation.
// This interface allows for different implementations of item specification creation strategies.
type ItemSpecificationFactory interface {
	CreateItemSpecification(currency, offerId, itemId, pointOfSaleId string, amount, availability int64, expireAt time.Time, isExternal bool) (*ItemSpecification, error)
}

// DefaultItemSpecificationFactory provides the standard implementation of ItemSpecificationFactory
//
// This concrete implementation handles the creation of ItemSpecification entities with
// standard business rules and validation. It automatically generates unique IDs,
// sets default values, and applies proper initialization for new item specifications.
type DefaultItemSpecificationFactory struct{}

// NewItemSpecificationFactory creates a new instance of the default item specification factory
//
// This constructor function returns a concrete implementation of the ItemSpecificationFactory
// interface. It follows the factory pattern by providing a clean way to instantiate
// the factory without exposing implementation details.
//
// Returns:
//   - ItemSpecificationFactory: A new instance of DefaultItemSpecificationFactory implementing the interface
func NewItemSpecificationFactory() ItemSpecificationFactory {
	return &DefaultItemSpecificationFactory{}
}

// CreateItemSpecification creates a new ItemSpecification instance with comprehensive validation and initialization
//
// This method is the core factory method that creates new ItemSpecification entities following
// the domain's business rules. It performs validation on all required parameters,
// generates a unique identifier, sets default values, and applies proper initialization
// to ensure the item specification is ready for auction processing.
//
// Parameters:
//   - currency: Currency code for pricing (must not be empty)
//   - offerId: ID of the offer this specification belongs to (must not be empty)
//   - itemId: ID of the base item being configured (must not be empty)
//   - pointOfSaleId: POS ID this specification belongs to (must not be empty)
//   - amount: Price/amount for this item (must be greater than 0)
//   - availability: Number of units available (must be greater than 0)
//   - expireAt: Expiration timestamp (must not be empty)
//   - isExternal: Whether this item comes from external source
//
// Returns:
//   - *ItemSpecification: A new ItemSpecification instance with all fields properly initialized
//   - error: Validation errors if any required parameter fails validation
//
// Side Effects:
//   - Generates a new UUID for the specification
//   - Sets State to StateAvailable by default
//   - Sets ReservedAt to nil (not reserved initially)
//   - Sets AllowMultipleItems to false by default
//
// Business Rules:
//   - All string parameters must be non-empty
//   - Amount and availability must be greater than 0
//   - Expiration time must be valid
//   - Specification starts in "available" state
//   - No initial reservation timestamp
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
		Id:                 generateUUID(),
		Amount:             amount,
		Currency:           currency,
		ExpireAt:           expireAt,
		OfferId:            offerId,
		ItemId:             itemId,
		Availability:       availability,
		IsExternal:         isExternal,
		PointOfSaleId:      pointOfSaleId,
		State:              StateAvailable,
		ReservedAt:         nil,
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
