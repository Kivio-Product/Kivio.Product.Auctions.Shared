package domain

import (
	"errors"
	"time"
)

// CustomerConfig represents customer-specific configuration settings for a Point of Sale
// 
// This entity stores customer preferences and settings that are specific to a particular
// Point of Sale (POS). It allows customization of customer behavior and purchasing
// rules on a per-POS basis, enabling different configurations for different business contexts.
type CustomerConfig struct {
	CustomerID         string    `json:"customer_id"`
	AllowMultipleItems bool      `json:"allow_multiple_items"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
	PointOfSaleId      string    `json:"point_of_sale_id"`
}

// CustomerConfigInput represents input data for creating or updating customer configurations
// 
// This struct contains the essential fields needed to create or update a customer
// configuration, excluding timestamp fields which are managed automatically by the system.
// It's typically used as input for API endpoints and service methods.
type CustomerConfigInput struct {
	CustomerID         string `json:"customer_id"`
	AllowMultipleItems bool   `json:"allow_multiple_items"`
	PointOfSaleId      string `json:"point_of_sale_id"`
}

// CustomerConfigRepository defines the contract for customer configuration data persistence operations
// 
// This interface abstracts the data access layer for customer configuration entities,
// providing a clean separation between business logic and persistence concerns.
// It defines the essential operations needed for managing customer-specific POS configurations.
type CustomerConfigRepository interface {
	// GetByCustomerID retrieves a customer configuration by customer ID
	// 
	// This method searches for a customer configuration using the customer ID.
	// Note: This method signature appears to be missing the PointOfSaleId parameter
	// which might be needed for proper identification in a multi-POS environment.
	//
	// Parameters:
	//   - customerID: The customer ID to search for
	//
	// Returns:
	//   - *CustomerConfig: Customer configuration if found, nil if not found
	//   - error: Database or lookup errors
	GetByCustomerID(customerID string) (*CustomerConfig, error)

	// Save persists a new customer configuration to the data store
	// 
	// This method saves a new customer configuration record to the database.
	// The configuration should be validated before calling this method.
	//
	// Parameters:
	//   - config: Customer configuration entity to persist
	//
	// Returns:
	//   - error: Database persistence errors
	Save(config *CustomerConfig) error

	// Update modifies an existing customer configuration in the data store
	// 
	// This method updates an existing customer configuration record with new information.
	// The UpdatedAt field should be set before calling this method.
	//
	// Parameters:
	//   - config: Customer configuration entity with updated information
	//
	// Returns:
	//   - error: Database update errors
	Update(config *CustomerConfig) error

	// Delete removes a customer configuration from the data store
	// 
	// This method removes a customer configuration record from the database.
	// Note: This method signature appears to be missing the PointOfSaleId parameter
	// which might be needed for proper identification in a multi-POS environment.
	//
	// Parameters:
	//   - customerID: The customer ID whose configuration should be deleted
	//
	// Returns:
	//   - error: Database deletion errors
	Delete(customerID string) error
}

// Update modifies the customer configuration settings
// 
// This method allows updating the customer configuration, specifically the
// AllowMultipleItems setting which controls whether the customer can purchase
// multiple items in a single order. It automatically updates the UpdatedAt timestamp.
//
// Parameters:
//   - allowMultipleItems: Whether to allow multiple items in orders
//
// Returns:
//   - error: Always returns nil (no validation errors possible)
//
// Side Effects:
//   - Modifies the AllowMultipleItems field
//   - Updates the UpdatedAt timestamp to current time
//
// Business Rules:
//   - No validation is performed on the parameter
//   - Change takes effect immediately
//   - UpdatedAt is automatically managed
func (c *CustomerConfig) Update(allowMultipleItems bool) error {
	c.AllowMultipleItems = allowMultipleItems
	c.UpdatedAt = time.Now()
	return nil
}

// Validate ensures the customer configuration has all required fields
// 
// This method performs validation on the customer configuration to ensure
// all required fields are present and valid before persistence operations.
// It checks for essential identifiers that are needed for proper configuration management.
//
// Returns:
//   - error: Returns validation errors if any required field is missing
//
// Side Effects:
//   - None (read-only validation)
//
// Business Rules:
//   - CustomerID cannot be empty (required for identification)
//   - PointOfSaleId cannot be empty (required for POS-specific configuration)
//   - AllowMultipleItems can be true or false (no validation needed)
//   - Timestamps are not validated (managed by system)
func (c *CustomerConfig) Validate() error {
	if c.CustomerID == "" {
		return errors.New("customer_id cannot be empty")
	}
	if c.PointOfSaleId == "" {
		return errors.New("point_of_sale_id cannot be empty")
	}
	return nil
}
