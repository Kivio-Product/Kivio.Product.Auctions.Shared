package domain

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// OfferFactory defines the contract for creating new Offer instances
//
// The factory pattern is used here to encapsulate the complex creation logic
// of Offer entities, ensuring proper initialization and validation. This interface
// allows for different implementations of offer creation strategies.
type OfferFactory interface {
	CreateOffer(name, description, posId, typer string, auctionTime, priceIncrease int64) (*Offer, error)
}

// DefaultOfferFactory provides the standard implementation of OfferFactory
//
// This concrete implementation handles the creation of Offer entities with
// standard business rules and validation. It automatically generates unique
// IDs, sets timestamps, and applies default values for new offers.
type DefaultOfferFactory struct{}

// NewOfferFactory creates a new instance of the default offer factory
//
// This constructor function returns a concrete implementation of the OfferFactory
// interface. It follows the factory pattern by providing a clean way to instantiate
// the factory without exposing implementation details.
//
// Returns:
//   - OfferFactory: A new instance of DefaultOfferFactory implementing the interface
func NewOfferFactory() OfferFactory {
	return &DefaultOfferFactory{}
}

// CreateOffer creates a new Offer instance with comprehensive validation and initialization
//
// This method is the core factory method that creates new Offer entities following
// the domain's business rules. It performs validation on all required parameters,
// generates a unique identifier, sets creation timestamp, and applies default values
// to ensure the offer is properly initialized for the auction system.
//
// Parameters:
//   - name: Display name/title of the offer (must not be empty)
//   - description: Detailed description of what's being auctioned (must not be empty)
//   - posId: Point of Sale ID this offer belongs to (must not be empty)
//   - typer: Type of auction (e.g., "Regular auction", "Flash sale") (must not be empty)
//   - auctionTime: Duration of the auction in seconds (no validation applied)
//
// Returns:
//   - *Offer: A new Offer instance with all fields properly initialized
//   - error: Validation errors if any required parameter is empty
//
// Side Effects:
//   - Generates a new UUID for the offer
//   - Sets CreatedAt to current timestamp
//   - Sets SortKey to "ACTIVE" by default
//   - Sets State to empty string (to be set by application layer)
//
// Business Rules:
//   - All string parameters must be non-empty
//   - OfferId is automatically generated using UUID
//   - CreatedAt is set to current time
//   - SortKey defaults to "ACTIVE" for immediate processing
//   - OfferTime is left as nil (to be set later if needed)
func (f *DefaultOfferFactory) CreateOffer(name, description, posId, typer string, auctionTime, priceIncrease int64) (*Offer, error) {

	if name == "" {
		return nil, fmt.Errorf("Name cannot be empty")
	}
	if description == "" {
		return nil, fmt.Errorf("Description cannot be empty")
	}
	if posId == "" {
		return nil, fmt.Errorf("PointOfSaleId cannot be empty")
	}
	if typer == "" {
		return nil, fmt.Errorf("Type cannot be empty")
	}

	return &Offer{
		OfferId:       generateUUID(),
		Name:          name,
		Description:   description,
		CreatedAt:     time.Now(),
		PosId:         posId,
		Type:          typer,
		AuctionTime:   auctionTime,
		PriceIncrease: priceIncrease,
		SortKey:       "ACTIVE",
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
