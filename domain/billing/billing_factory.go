package domain

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// BillingFactory defines the contract for creating new Billing instances
// 
// The factory pattern is used here to encapsulate the complex creation logic
// of Billing entities, ensuring proper initialization and validation.
// This interface allows for different implementations of billing creation strategies.
type BillingFactory interface {
	CreateBilling(provider, posId string, customer *Customer, invoiceConfig *InvoiceConfig) (*Billing, error)
}

// DefaultBillingFactory provides the standard implementation of BillingFactory
// 
// This concrete implementation handles the creation of Billing entities with
// standard business rules and validation. It automatically generates unique IDs,
// sets default values, and applies proper initialization for new billing records.
type DefaultBillingFactory struct{}

// NewBillingFactory creates a new instance of the default billing factory
// 
// This constructor function returns a concrete implementation of the BillingFactory
// interface. It follows the factory pattern by providing a clean way to instantiate
// the factory without exposing implementation details.
//
// Returns:
//   - BillingFactory: A new instance of DefaultBillingFactory implementing the interface
func NewBillingFactory() BillingFactory {
	return &DefaultBillingFactory{}
}

// CreateBilling creates a new Billing instance with comprehensive validation and initialization
// 
// This method is the core factory method that creates new Billing entities following
// the domain's business rules. It performs validation on all required parameters,
// generates a unique identifier, sets default values, and applies proper initialization
// to ensure the billing record is ready for payment processing.
//
// Parameters:
//   - provider: Payment provider (must not be empty)
//   - posId: Point of Sale ID (must not be empty)
//   - customer: Customer information (must not be nil and must be valid)
//   - invoiceConfig: Invoice configuration (must not be nil)
//
// Returns:
//   - *Billing: A new Billing instance with all fields properly initialized
//   - error: Validation errors if any required parameter fails validation
//
// Side Effects:
//   - Generates a new UUID for the billing record
//   - Sets State to "Pending" by default
//   - Sets CreatedAt to current timestamp
//   - Sets TransactionId and PayloadType to empty strings
//   - Sets ConfirmedAt to zero time
//
// Business Rules:
//   - Provider cannot be empty
//   - Customer cannot be nil
//   - InvoiceConfig cannot be nil
//   - Customer PersonType must be "Person"
//   - Customer IDType must be "13" (cédula)
//   - POS ID cannot be empty
//   - Billing starts in "Pending" state
func (f *DefaultBillingFactory) CreateBilling(provider, posId string, customer *Customer, invoiceConfig *InvoiceConfig) (*Billing, error) {
	if provider == "" {
		return nil, fmt.Errorf("provider no puede estar vacío")
	}
	if customer == nil {
		return nil, fmt.Errorf("customer no puede estar vacío")
	}
	if invoiceConfig == nil {
		return nil, fmt.Errorf("invoiceConfig no puede estar vacío")
	}
	if customer.PersonType != "Person" {
		return nil, fmt.Errorf("PersonType debe ser 'Person'")
	}
	if customer.IDType != "13" {
		return nil, fmt.Errorf("IDType debe ser '13' (cédula)")
	}

	if posId == "" {
		return nil, fmt.Errorf("posId no puede estar vacío")
	}

	return &Billing{
		Id:            generateUUID(),
		State:         "Pending",
		Provider:      provider,
		CreatedAt:     time.Now(),
		TransactionId: "",
		PayloadType:   "",
		PointOfSaleId: posId,
		ConfirmedAt:   time.Time{},
		Customer:      customer,
		InvoiceConfig: invoiceConfig,
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
