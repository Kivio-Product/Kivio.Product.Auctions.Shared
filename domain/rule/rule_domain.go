package domain

import "errors"

type Rule struct {
	RuleId              string
	ExternalId          string
	ItemSpecificationId string
	OfferId             string
	State               string
	PosId               string
}

var (
	StateCreated  = "Created"
	StateActive   = "Active"
	StateInactive = "Inactive"
)

// GenerateCreatedState sets the rule state to "Created" and returns the modified rule
// 
// This function initializes a newly created rule with the appropriate
// created state. It ensures that newly created rule entities are
// immediately available for processing in the system.
//
// Parameters:
//   - rule: Pointer to the rule entity to modify
//
// Returns:
//   - *Rule: Modified rule with state set to "Created"
//
// Side Effects:
//   - Modifies the state field of the input entity
//
// Technical Details:
//   - Sets state to StateCreated constant ("Created")
//   - Returns the same pointer for method chaining
//   - Used during rule creation workflow
func GenerateCreatedState(rule *Rule) *Rule {
	rule.State = StateCreated
	return rule
}

// Update modifies the rule properties with new values, validating required fields
// 
// This method updates the rule entity with new information while ensuring
// all required fields are properly validated. It performs comprehensive validation
// before applying any changes to the entity properties.
//
// Parameters:
//   - externalId: External system identifier for the rule
//   - itemSpecificationId: Unique identifier of the item specification
//   - offerId: Unique identifier of the offer this rule belongs to
//
// Returns:
//   - error: Returns error if validation fails for any required field
//
// Side Effects:
//   - Modifies entity properties: ExternalId, ItemSpecificationId, OfferId
//
// Technical Details:
//   - Validates all parameters are non-empty strings
//   - Returns specific error messages for each validation failure
//   - Updates entity fields only after successful validation
//   - Uses Spanish error messages for user-facing validation
func (o *Rule) Update(externalId, itemSpecificationId, offerId string) error {
	if externalId == "" {
		return errors.New("El externalId no puede estar vacío")
	}
	if itemSpecificationId == "" {
		return errors.New("La itemId no puede estar vacía")
	}
	if offerId == "" {
		return errors.New("La offerId no puede estar vacía")
	}
	o.ExternalId = externalId
	o.ItemSpecificationId = itemSpecificationId
	o.OfferId = offerId
	return nil
}

// UpdateState modifies the rule state with validation
// 
// This method updates the rule state while ensuring the new state is valid.
// It performs validation before applying the state change to maintain
// data integrity.
//
// Parameters:
//   - state: New state to set for the rule
//
// Returns:
//   - error: Returns error if validation fails
//
// Side Effects:
//   - Modifies the state field of the rule entity
//
// Technical Details:
//   - Validates state parameter is non-empty
//   - Returns Spanish error message for validation failure
//   - Updates state field only after successful validation
//   - Should be used with valid state constants
func (o *Rule) UpdateState(state string) error {
	if state == "" {
		return errors.New("El estado no puede estar vacío")
	}
	o.State = state
	return nil
}
