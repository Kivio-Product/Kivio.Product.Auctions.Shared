package domain

import (
	"errors"
	"time"
)

type Offer struct {
	OfferId     string
	CreatedAt   time.Time
	Description string
	Name        string
	PosId       string
	State       string
	Type        string
	AuctionTime int64
	SortKey     string
	OfferTime   *time.Time
}

var (
	StateInactive = "Created"
	StateActive   = "Offered"
)

// Update modifies the core details of an offer with comprehensive validation
// 
// This function allows updating the essential information of an offer including
// its name, description, and auction duration. It performs validation to ensure
// data integrity and automatically sets the SortKey to "ACTIVE" to indicate
// the offer is ready for auction processing.
//
// Parameters:
//   - name: The display name/title of the offer (must not be empty)
//   - description: Detailed description of what's being auctioned (must not be empty)
//   - auctionTime: Duration of the auction in seconds (must be positive)
//
// Returns:
//   - error: Returns validation errors if any parameter fails validation
//
// Side Effects:
//   - Modifies the offer's Name, Description, AuctionTime, and SortKey fields
//   - Automatically sets SortKey to "ACTIVE" regardless of current state
//
// Business Rules:
//   - Name cannot be empty (required for display purposes)
//   - Description cannot be empty (required for user understanding)
//   - AuctionTime must be positive (prevents invalid auction durations)
//   - SortKey is automatically set to "ACTIVE" to enable auction processing
func (o *Offer) Update(name, description string, auctionTime int64) error {
	if name == "" {
		return errors.New("El nombre no puede estar vacío")
	}
	if description == "" {
		return errors.New("La descripcion no puede estar vacía")
	}
	if auctionTime < 0 {
		return errors.New("el auctionTime debe ser mayor a cero")
	}
	o.Name = name
	o.Description = description
	o.AuctionTime = auctionTime
	o.SortKey = "ACTIVE"
	return nil
}

// UpdateState changes the current state of the offer
// 
// This function is used to transition offers between different lifecycle states
// in the auction system. State transitions are crucial for controlling auction flow
// and determining when offers can be processed or modified.
//
// Parameters:
//   - state: The new state to set for the offer (must not be empty)
//
// Returns:
//   - error: Returns an error if the state parameter is empty
//
// Side Effects:
//   - Modifies the offer's State field
//   - No validation is performed on the state value itself
//
// Business Rules:
//   - State cannot be empty (validates input)
//   - No restrictions on which states can transition to which other states
//   - State changes are immediate and don't trigger additional business logic
func (o *Offer) UpdateState(state string) error {
	if state == "" {
		return errors.New("El estado no puede estar vacío")
	}
	o.State = state
	return nil
}

// SetOfferTime sets the specific time when the offer becomes active
// 
// This function allows to set the exact moment when an offer transitions a state.
//
// Parameters:
//   - t: The exact time when the offer should become active
//
// Returns:
//   - None (void function)
//
// Side Effects:
//   - Modifies the offer's OfferTime field by setting it to a pointer to the provided time
//   - The OfferTime field is a pointer to allow for nil values (not yet scheduled)
//
// Business Rules:
//   - No validation is performed on the time value
//   - The time can be in the past, present, or future
//   - Setting OfferTime doesn't automatically change the offer's state
//   - OfferTime is used by the application layer to determine when to activate offers
func (o *Offer) SetOfferTime(t time.Time) {
	o.OfferTime = &t
}
