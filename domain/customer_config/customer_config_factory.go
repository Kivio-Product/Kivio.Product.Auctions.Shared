package domain

import (
	"time"
)

// CustomerConfigFactory defines the contract for creating new CustomerConfig instances
// 
// The factory pattern is used here to encapsulate the creation logic of CustomerConfig
// entities, ensuring proper initialization and validation. This interface allows for
// different implementations of customer configuration creation strategies.
type CustomerConfigFactory interface {
	CreateCustomerConfig(input CustomerConfigInput) (*CustomerConfig, error)
}

// customerConfigFactory provides the standard implementation of CustomerConfigFactory
// 
// This concrete implementation handles the creation of CustomerConfig entities with
// standard business rules and validation. It automatically sets timestamps and
// applies proper initialization for new customer configurations.
type customerConfigFactory struct{}

// NewCustomerConfigFactory creates a new instance of the customer configuration factory
// 
// This constructor function returns a concrete implementation of the CustomerConfigFactory
// interface. It follows the factory pattern by providing a clean way to instantiate
// the factory without exposing implementation details.
//
// Returns:
//   - CustomerConfigFactory: A new instance of customerConfigFactory implementing the interface
func NewCustomerConfigFactory() CustomerConfigFactory {
	return &customerConfigFactory{}
}

// CreateCustomerConfig creates a new CustomerConfig instance with validation and initialization
// 
// This method is the core factory method that creates new CustomerConfig entities following
// the domain's business rules. It performs validation on the input data, sets timestamps,
// and applies proper initialization to ensure the customer configuration is ready for use.
//
// Parameters:
//   - input: CustomerConfigInput containing the configuration data
//
// Returns:
//   - *CustomerConfig: A new CustomerConfig instance with all fields properly initialized
//   - error: Validation errors if the input data fails validation
//
// Side Effects:
//   - Sets CreatedAt to current timestamp
//   - Sets UpdatedAt to current timestamp
//   - Performs validation on the created configuration
//
// Business Rules:
//   - CustomerID must not be empty (validated by config.Validate())
//   - PointOfSaleId must not be empty (validated by config.Validate())
//   - AllowMultipleItems can be true or false
//   - Timestamps are automatically set to current time
//   - Configuration is validated before returning
func (f *customerConfigFactory) CreateCustomerConfig(input CustomerConfigInput) (*CustomerConfig, error) {
	config := &CustomerConfig{
		CustomerID:         input.CustomerID,
		AllowMultipleItems: input.AllowMultipleItems,
		PointOfSaleId:      input.PointOfSaleId,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}
