package domain

import (
	"fmt"

	"github.com/google/uuid"
)

type RuleSpecificationFactory interface {
	CreateRuleSpecification(ruleId, typer, operator, parameter, offerId, itemName string) (*RuleSpecification, error)
}

type DefaultRuleSpecificationFactory struct{}

// NewRuleSpecificationFactory creates a new instance of the default rule specification factory
// 
// This constructor initializes the default rule specification factory implementation.
// It provides a concrete implementation of the RuleSpecificationFactory interface for creating
// new rule specification entities with proper validation and initialization.
//
// Returns:
//   - RuleSpecificationFactory: Configured factory instance ready for rule specification creation
//
// Side Effects:
//   - None (pure constructor)
//
// Technical Details:
//   - Returns DefaultRuleSpecificationFactory instance
//   - Implements RuleSpecificationFactory interface
//   - Enables dependency injection pattern
func NewRuleSpecificationFactory() RuleSpecificationFactory {
	return &DefaultRuleSpecificationFactory{}
}

// CreateRuleSpecification creates a new rule specification instance with the provided details, validating required fields
// 
// This method creates a new rule specification entity with comprehensive validation of all
// required fields. It generates a unique identifier and ensures all mandatory
// information is present before entity creation.
//
// Parameters:
//   - ruleId: Unique identifier of the parent rule
//   - typer: Type of the rule specification (e.g., "price", "quantity", "category")
//   - operator: Operator for the rule (e.g., "equals", "greater_than", "less_than")
//   - parameter: Parameter value for the rule operation
//   - offerId: Unique identifier of the offer this rule specification belongs to
//   - itemName: Name of the item this rule specification applies to
//
// Returns:
//   - *RuleSpecification: New rule specification instance with generated ID
//   - error: Returns error if validation fails for any required field
//
// Side Effects:
//   - Generates new UUID for rule specification identification
//
// Technical Details:
//   - Validates all parameters are non-empty strings
//   - Generates UUID using google/uuid package
//   - Sets RuleSpecificationId field with generated UUID
//   - Returns specific error messages for each validation failure
//   - Creates entity with all required fields populated
//   - State defaults to inactive (not explicitly set)
func (f *DefaultRuleSpecificationFactory) CreateRuleSpecification(ruleId, typer, operator, parameter, offerId, itemName string) (*RuleSpecification, error) {
	if ruleId == "" {
		return nil, fmt.Errorf("RuleId cannot be empty")
	}
	if typer == "" {
		return nil, fmt.Errorf("Type cannot be empty")
	}
	if operator == "" {
		return nil, fmt.Errorf("Operator cannot be empty")
	}
	if parameter == "" {
		return nil, fmt.Errorf("Parameter cannot be empty")
	}
	if offerId == "" {
		return nil, fmt.Errorf("offerId cannot be empty")
	}
	return &RuleSpecification{
		RuleSpecificationId: generateUUID(),
		RuleId:              ruleId,
		Type:                typer,
		Operator:            operator,
		Parameter:           parameter,
		OfferId:             offerId,
		ItemName:            itemName,
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
