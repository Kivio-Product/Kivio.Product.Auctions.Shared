package domain

import (
	"fmt"

	"github.com/google/uuid"
)

type RuleFactory interface {
	CreateRule(offerId, externalId, itemId, posId string) (*Rule, error)
}

type DefaultRuleFactory struct{}

// NewRuleFactory creates a new instance of the default rule factory
// 
// This constructor initializes the default rule factory implementation.
// It provides a concrete implementation of the RuleFactory interface for creating
// new rule entities with proper validation and initialization.
//
// Returns:
//   - RuleFactory: Configured factory instance ready for rule creation
//
// Side Effects:
//   - None (pure constructor)
//
// Technical Details:
//   - Returns DefaultRuleFactory instance
//   - Implements RuleFactory interface
//   - Enables dependency injection pattern
func NewRuleFactory() RuleFactory {
	return &DefaultRuleFactory{}
}

// CreateRule creates a new rule instance with the provided details, validating required fields
// 
// This method creates a new rule entity with comprehensive validation of all
// required fields. It generates a unique identifier and ensures all mandatory
// information is present before entity creation.
//
// Parameters:
//   - offerId: Unique identifier of the offer this rule belongs to
//   - externalId: External system identifier for the rule
//   - itemSpecificationId: Unique identifier of the item specification
//   - posId: Unique identifier of the point of sale
//
// Returns:
//   - *Rule: New rule instance with generated ID
//   - error: Returns error if validation fails for any required field
//
// Side Effects:
//   - Generates new UUID for rule identification
//
// Technical Details:
//   - Validates all parameters are non-empty strings
//   - Generates UUID using google/uuid package
//   - Sets RuleId field with generated UUID
//   - Returns specific error messages for each validation failure
//   - Creates entity with all required fields populated
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
