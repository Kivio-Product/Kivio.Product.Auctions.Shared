package domain

import (
	"errors"
	"time"
)

type PointOfSale struct {
	PointOfSaleId string
	CreateAt      time.Time
	Description   string
	Name          string
	State         string
	UserId        string
	Url           string
}

var (
	StateInactive = "Inactive"
	StateActive   = "Active"
)

// GenerateCreatedState sets the point of sale state to "Active" and returns the modified entity
// 
// This function initializes a newly created point of sale with the appropriate
// active state. It ensures that newly created point of sale entities are
// immediately available for use in the system.
//
// Parameters:
//   - pos: Pointer to the point of sale entity to modify
//
// Returns:
//   - *PointOfSale: Modified point of sale with state set to "Active"
//
// Side Effects:
//   - Modifies the state field of the input entity
//
// Technical Details:
//   - Sets state to StateActive constant ("Active")
//   - Returns the same pointer for method chaining
//   - Used during point of sale creation workflow
func GenerateCreatedState(pos *PointOfSale) *PointOfSale {
	pos.State = StateActive
	return pos
}

// Update modifies the point of sale properties with new values, validating required fields
// 
// This method updates the point of sale entity with new information while ensuring
// all required fields are properly validated. It performs comprehensive validation
// before applying any changes to the entity properties.
//
// Parameters:
//   - name: New display name for the point of sale
//   - description: New descriptive text about the point of sale
//   - pointOfSaleId: Unique identifier of the point of sale
//   - userId: User identifier associated with the point of sale
//
// Returns:
//   - error: Returns error if validation fails for any required field
//
// Side Effects:
//   - Modifies entity properties: Name, Description, PointOfSaleId, UserId
//
// Technical Details:
//   - Validates all parameters are non-empty strings
//   - Returns specific error messages for each validation failure
//   - Updates entity fields only after successful validation
//   - Uses Spanish error messages for user-facing validation
func (o *PointOfSale) Update(name, description, pointOfSaleId, userId string) error {
	if name == "" {
		return errors.New("El nombre no puede estar vacío")
	}
	if description == "" {
		return errors.New("La descripcion no puede estar vacía")
	}
	if pointOfSaleId == "" {
		return errors.New("El punto de venta no puede estar vacío")
	}
	if userId == "" {
		return errors.New("El userId no puede estar vacío")
	}
	o.Name = name
	o.Description = description
	o.PointOfSaleId = pointOfSaleId
	o.UserId = userId
	return nil
}
