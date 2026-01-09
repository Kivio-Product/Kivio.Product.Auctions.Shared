package domain

import "errors"

type RuleSpecification struct {
	RuleSpecificationId string
	RuleId              string
	OfferId             string
	Type                string
	Operator            string
	Parameter           string
	ItemName            string
	State               bool
}

// GenerateInactiveState sets the rule specification state to inactive and returns the modified rule
// 
// This function initializes a rule specification with an inactive state.
// It ensures that newly created rule specifications are set to inactive
// by default, requiring explicit activation for use in the system.
//
// Parameters:
//   - rule: Pointer to the rule specification entity to modify
//
// Returns:
//   - *RuleSpecification: Modified rule specification with state set to inactive (false)
//
// Side Effects:
//   - Modifies the state field of the input entity
//
// Technical Details:
//   - Sets state to false (inactive)
//   - Returns the same pointer for method chaining
//   - Used during rule specification creation workflow
//   - Ensures rule specifications start in inactive state
func GenerateInactiveState(rule *RuleSpecification) *RuleSpecification {
	rule.State = false
	return rule
}

// Update modifies the rule specification properties with new values, validating required fields
// 
// This method updates the rule specification entity with new information while ensuring
// all required fields are properly validated. It performs comprehensive validation
// before applying any changes to the entity properties.
//
// Parameters:
//   - typer: Type of the rule specification (e.g., "price", "quantity", "category")
//   - operator: Operator for the rule (e.g., "equals", "greater_than", "less_than")
//   - parameter: Parameter value for the rule operation
//
// Returns:
//   - error: Returns error if validation fails for any required field
//
// Side Effects:
//   - Modifies entity properties: Type, Operator, Parameter
//
// Technical Details:
//   - Validates all parameters are non-empty strings
//   - Returns specific error messages for each validation failure
//   - Updates entity fields only after successful validation
//   - Uses Spanish error messages for user-facing validation
//   - Maintains data integrity through validation
func (o *RuleSpecification) Update(typer, operator, parameter string) error {
	if typer == "" {
		return errors.New("El type no puede estar vacío")
	}
	if operator == "" {
		return errors.New("La operacion no puede estar vacía")
	}
	if parameter == "" {
		return errors.New("el parametro no puede estar vacía")
	}
	o.Type = typer
	o.Operator = operator
	o.Parameter = parameter
	return nil
}
