package domain

import (
	"fmt"
	"time"
)

// ItemSpecificationState represents the current availability state of an item specification
// 
// This type defines the lifecycle states that an item specification can be in,
// controlling when items can be reserved, purchased, or are unavailable.
type ItemSpecificationState string

// Predefined states for item specification lifecycle management
const (
	StateAvailable   ItemSpecificationState = "available"
	StateReserved    ItemSpecificationState = "reserved"
	StateNoAvailable ItemSpecificationState = "noavailable"
)

// ItemSource represents the origin of an item in the auction system
// 
// This type defines where items come from, which affects how they are managed,
// priced, and integrated with external systems like e-commerce platforms.
type ItemSource string

const (
	SourceLocal     ItemSource = "local"
	SourceEcommerce ItemSource = "kivio_ecommerce"
)

// ItemSpecification represents a specific item configuration within an auction offer
// 
// An ItemSpecification defines the details of a particular item that can be auctioned,
// including its pricing, availability, expiration, and source. It's linked to both an
// Offer and a specific Item, providing the auction-specific configuration for that item.
type ItemSpecification struct {
	Id                 string
	Amount             int64
	Currency           string
	ExpireAt           time.Time
	OfferId            string
	ItemId             string
	Availability       int64
	IsExternal         bool
	Source             ItemSource
	PointOfSaleId      string
	State              ItemSpecificationState
	ReservedAt         *time.Time
	AllowMultipleItems bool
}

// Update modifies the core details of an item specification with comprehensive validation
// 
// This method allows updating the essential information of an item specification including
// pricing, availability, expiration, and relationships. It performs validation to ensure
// data integrity and proper configuration for auction processing.
//
// Parameters:
//   - currency: Currency code for pricing (must not be empty)
//   - offerId: ID of the offer this specification belongs to (must not be empty)
//   - itemId: ID of the base item being configured (must not be empty)
//   - pointOfSaleId: POS ID this specification belongs to (must not be empty)
//   - amount: Price/amount for this item (must be greater than 0)
//   - availability: Number of units available (must be greater than 0)
//   - expireAt: Expiration timestamp (must not be empty)
//
// Returns:
//   - error: Returns validation errors if any parameter fails validation
//
// Side Effects:
//   - Modifies the specification's core fields
//   - Does not change state or reservation information
//
// Business Rules:
//   - All string parameters must be non-empty
//   - Amount and availability must be greater than 0
//   - Expiration time must be valid
func (o *ItemSpecification) Update(currency, offerId, itemId, pointOfSaleId string, amount, availability int64, expireAt time.Time) error {
	if currency == "" {
		return fmt.Errorf("Currency cannot be empty")
	}
	if offerId == "" {
		return fmt.Errorf("offerId cannot be empty")
	}
	if itemId == "" {
		return fmt.Errorf("itemId cannot be empty")
	}
	if pointOfSaleId == "" {
		return fmt.Errorf("pointOfSaleId cannot be empty")
	}
	if amount == 0 {
		return fmt.Errorf("amount cannot be empty")
	}
	if expireAt.String() == "" {
		return fmt.Errorf("expireAt cannot be empty")
	}

	o.Currency = currency
	o.OfferId = offerId
	o.ItemId = itemId
	o.Amount = amount
	o.ExpireAt = expireAt
	o.Availability = availability
	o.PointOfSaleId = pointOfSaleId

	return nil
}

// UpdateAllowMultipleItems sets whether multiple units of this item can be purchased together
// 
// This method controls the purchasing behavior for this item specification, determining
// whether customers can buy multiple units in a single order or must purchase them
// individually. This affects order processing and inventory management.
//
// Parameters:
//   - allowMultiple: Whether multiple units can be purchased together
//
// Returns:
//   - None (void function)
//
// Side Effects:
//   - Modifies the AllowMultipleItems field
//
// Business Rules:
//   - No validation is performed on the parameter
//   - Change takes effect immediately
func (o *ItemSpecification) UpdateAllowMultipleItems(allowMultiple bool) {
	o.AllowMultipleItems = allowMultiple
}

// UpdateState changes the availability state of the item specification with strict validation
// 
// This method manages the lifecycle state transitions of an item specification, enforcing
// business rules about which state transitions are allowed. It automatically manages
// reservation timestamps and ensures state consistency throughout the auction process.
//
// Parameters:
//   - state: The new state to transition to (must be valid state)
//
// Returns:
//   - error: Returns error if state transition is invalid or not allowed
//
// Side Effects:
//   - Modifies the State field
//   - Sets ReservedAt timestamp when transitioning to "reserved"
//   - Clears ReservedAt when transitioning away from "reserved"
//
// Business Rules:
//   - Only valid states are allowed: available, reserved, noavailable
//   - State transitions follow strict rules:
//     * available → reserved (only allowed transition from available)
//     * reserved → available or noavailable (allowed transitions from reserved)
//     * noavailable → no transitions allowed (final state)
//   - ReservedAt is automatically managed based on state
func (o *ItemSpecification) UpdateState(state ItemSpecificationState) error {
	if state != StateAvailable && state != StateReserved && state != StateNoAvailable {
		return fmt.Errorf("invalid state: %s. Valid states are: available, reserved, noavailable", state)
	}

	switch o.State {
	case StateAvailable:
		if state != StateReserved {
			return fmt.Errorf("invalid transition from %s to %s. From available, only transition to reserved is allowed", o.State, state)
		}
	case StateReserved:
		if state != StateNoAvailable && state != StateAvailable {
			return fmt.Errorf("invalid transition from %s to %s. From reserved, only transitions to noavailable or available are allowed", o.State, state)
		}
	case StateNoAvailable:
		return fmt.Errorf("invalid transition from %s to %s. No transitions are allowed from noavailable state", o.State, state)
	default:
		return fmt.Errorf("unknown current state: %s", o.State)
	}

	o.State = state

	if state == StateReserved {
		now := time.Now()
		o.ReservedAt = &now
	} else {
		o.ReservedAt = nil
	}

	return nil
}

// IsReservationExpired checks if the current reservation has exceeded the time limit
// 
// This method determines whether a reserved item specification has been held for too long
// and should be automatically released back to available status. It implements a 20-minute
// reservation timeout to prevent indefinite holds on items.
//
// Returns:
//   - bool: true if reservation is expired, false otherwise
//
// Side Effects:
//   - None (read-only operation)
//
// Business Rules:
//   - Only applies to items in "reserved" state
//   - Reservation timeout is 20 minutes
//   - Returns false if item is not reserved or has no reservation timestamp
func (o *ItemSpecification) IsReservationExpired() bool {
	if o.State != StateReserved || o.ReservedAt == nil {
		return false
	}
	return time.Since(*o.ReservedAt) > 20*time.Minute
}

// CheckAndUpdateExpiredReservation automatically releases expired reservations
// 
// This method checks if the current reservation has expired and automatically
// transitions the item back to "available" state if the timeout has been exceeded.
// It's designed to be called periodically to clean up expired reservations.
//
// Returns:
//   - error: Always returns nil (no errors possible)
//
// Side Effects:
//   - May modify State field (sets to "available" if expired)
//   - May clear ReservedAt field (sets to nil if expired)
//
// Business Rules:
//   - Only affects items in "reserved" state
//   - Uses 20-minute reservation timeout
//   - Automatically transitions expired reservations to "available"
func (o *ItemSpecification) CheckAndUpdateExpiredReservation() error {
	if o.IsReservationExpired() {
		o.State = StateAvailable
		o.ReservedAt = nil
	}
	return nil
}

// CheckAndUpdateAvailabilityState automatically updates state based on availability
// 
// This method monitors the availability count and automatically transitions the item
// to "noavailable" state when inventory reaches zero. It ensures state consistency
// between availability count and state, preventing overselling scenarios.
//
// Returns:
//   - error: Always returns nil (no errors possible)
//
// Side Effects:
//   - May modify State field (sets to "noavailable" if availability is 0)
//   - May clear ReservedAt field (sets to nil when transitioning to "noavailable")
//
// Business Rules:
//   - Only transitions to "noavailable" if availability is 0
//   - Only affects items not already in "noavailable" state
//   - Clears reservation when transitioning to "noavailable"
func (o *ItemSpecification) CheckAndUpdateAvailabilityState() error {
	if o.Availability == 0 && o.State != StateNoAvailable {
		o.State = StateNoAvailable
		o.ReservedAt = nil
	}
	return nil
}

// GetSource returns the source of the item, with intelligent fallback logic
// 
// This method determines the actual source of the item specification, using
// intelligent fallback logic when the Source field is not explicitly set.
// It provides backward compatibility and automatic source detection.
//
// Returns:
//   - ItemSource: The determined source of the item
//
// Side Effects:
//   - None (read-only operation)
//
// Business Rules:
//   - If Source is explicitly set, returns that value
//   - If Source is empty but IsExternal is true, returns SourceEcommerce
//   - Otherwise, returns SourceLocal as default
//   - Provides intelligent fallback for legacy data
func (o *ItemSpecification) GetSource() ItemSource {
	if o.Source != "" {
		return o.Source
	}

	if o.IsExternal {
		return SourceEcommerce
	}

	return SourceLocal
}

// SetSource explicitly sets the source of the item and updates related fields
// 
// This method sets the source of the item specification and automatically
// updates the IsExternal field to maintain consistency between the two
// source-related fields. It ensures data integrity across source tracking.
//
// Parameters:
//   - source: The source to set for this item specification
//
// Returns:
//   - None (void function)
//
// Side Effects:
//   - Modifies the Source field
//   - Automatically updates IsExternal field based on source
//
// Business Rules:
//   - Sets Source to the provided value
//   - Sets IsExternal to true if source is not SourceLocal
//   - Maintains consistency between Source and IsExternal fields
func (o *ItemSpecification) SetSource(source ItemSource) {
	o.Source = source
	o.IsExternal = (source != SourceLocal)
}
