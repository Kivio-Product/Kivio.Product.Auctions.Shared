package domain

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

type PosFactory interface {
	CreatePointOfSale(description, name, userId, url string) (*PointOfSale, error)
}

type DefaultPosFactory struct{}

// NewPosFactory creates a new instance of the default point of sale factory
// 
// This constructor initializes the default point of sale factory implementation.
// It provides a concrete implementation of the PosFactory interface for creating
// new point of sale entities with proper validation and initialization.
//
// Returns:
//   - PosFactory: Configured factory instance ready for point of sale creation
//
// Side Effects:
//   - None (pure constructor)
//
// Technical Details:
//   - Returns DefaultPosFactory instance
//   - Implements PosFactory interface
//   - Enables dependency injection pattern
func NewPosFactory() PosFactory {
	return &DefaultPosFactory{}
}

// CreatePointOfSale creates a new point of sale instance with the provided details, validating required fields
// 
// This method creates a new point of sale entity with comprehensive validation of all
// required fields. It generates a unique identifier, sets the creation timestamp,
// and ensures all mandatory information is present before entity creation.
//
// Parameters:
//   - description: Descriptive text about the point of sale
//   - name: Display name for the point of sale
//   - userId: Unique identifier of the user creating the point of sale
//   - url: Web URL associated with the point of sale
//
// Returns:
//   - *PointOfSale: New point of sale instance with generated ID and timestamp
//   - error: Returns error if validation fails for any required field
//
// Side Effects:
//   - Generates new UUID for point of sale identification
//   - Sets creation timestamp to current time
//
// Technical Details:
//   - Validates all parameters are non-empty strings
//   - Generates UUID using google/uuid package
//   - Sets CreateAt field to time.Now()
//   - Returns specific error messages for each validation failure
//   - Creates entity with all required fields populated
func (f *DefaultPosFactory) CreatePointOfSale(description, name, userId, url string) (*PointOfSale, error) {
	if name == "" {
		return nil, fmt.Errorf("Name cannot be empty")
	}
	if description == "" {
		return nil, fmt.Errorf("Description cannot be empty")
	}
	if userId == "" {
		return nil, fmt.Errorf("UserId cannot be empty")
	}
	if url == "" {
		return nil, fmt.Errorf("Url cannot be empty")
	}
	return &PointOfSale{
		PointOfSaleId: generateUUID(),
		CreateAt:      time.Now(),
		Description:   description,
		Name:          name,
		UserId:        userId,
		Url:           url,
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
