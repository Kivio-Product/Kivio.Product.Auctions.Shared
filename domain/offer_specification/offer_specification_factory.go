package domain

import (
	"fmt"
	"time"
)

type OfferSpecificationFactory interface {
	CreateOfferSpecification(externalID, offerID string) (*OfferSpecification, error)
}

type DefaultOfferSpecificationFactory struct{}

// NewOfferSpecificationFactory creates a new instance of the default offer specification factory
// 
// This constructor initializes the default offer specification factory implementation.
// It provides a concrete implementation of the OfferSpecificationFactory interface for creating
// new offer specification entities with proper validation and initialization.
//
// Returns:
//   - OfferSpecificationFactory: Configured factory instance ready for offer specification creation
//
// Side Effects:
//   - None (pure constructor)
//
// Technical Details:
//   - Returns DefaultOfferSpecificationFactory instance
//   - Implements OfferSpecificationFactory interface
//   - Enables dependency injection pattern
func NewOfferSpecificationFactory() OfferSpecificationFactory {
	return &DefaultOfferSpecificationFactory{}
}

// CreateOfferSpecification creates a new offer specification instance with the provided details, validating required fields
// 
// This method creates a new offer specification entity with comprehensive validation of all
// required fields. It ensures all mandatory information is present before entity creation
// and sets the creation timestamp to the current time.
//
// Parameters:
//   - externalID: External identifier associated with the offer specification
//   - offerID: Unique identifier of the offer this specification belongs to
//
// Returns:
//   - *OfferSpecification: New offer specification instance with generated timestamp
//   - error: Returns error if validation fails for any required field
//
// Side Effects:
//   - Sets creation timestamp to current time
//
// Technical Details:
//   - Validates externalID and offerID are non-empty strings
//   - Sets CreatedAt field to time.Now()
//   - Returns specific error messages for each validation failure
//   - Creates entity with all required fields populated
//   - No UUID generation required (uses external identifiers)
func (f *DefaultOfferSpecificationFactory) CreateOfferSpecification(externalID, offerID string) (*OfferSpecification, error) {
	if externalID == "" {
		return nil, fmt.Errorf("ExternalID cannot be empty")
	}
	if offerID == "" {
		return nil, fmt.Errorf("OfferID cannot be empty")
	}
	return &OfferSpecification{
		ExternalID: externalID,
		CreatedAt:  time.Now(),
		OfferID:    offerID,
	}, nil
}
