package domain

import (
	"context"
	"time"
)

// Customer represents a customer entity in the auction system
// 
// A Customer entity contains the essential information needed to identify and
// manage customers within the auction system. It includes references to external
// customer systems and address information for billing and shipping purposes.
type Customer struct {
	ID                 string    `json:"id" dynamodbav:"id"`
	Email              string    `json:"email" dynamodbav:"email"`
	ExternalCustomerID string    `json:"externalCustomerId" dynamodbav:"externalCustomerId"`
	BillingAddressID   string    `json:"billingAddressId" dynamodbav:"billingAddressId"`
	ShippingAddressID  string    `json:"shippingAddressId" dynamodbav:"shippingAddressId"`
	CreatedAt          time.Time `json:"createdAt" dynamodbav:"createdAt"`
	UpdatedAt          time.Time `json:"updatedAt" dynamodbav:"updatedAt"`
}

// CustomerRepository defines the contract for customer data persistence operations
// 
// This interface abstracts the data access layer for customer entities, providing
// a clean separation between business logic and persistence concerns. It defines
// the essential operations needed for customer management in the auction system.
type CustomerRepository interface {
	// GetByEmail retrieves a customer by their email address
	// 
	// This method searches for a customer using their email as the primary identifier.
	// Email is used as the lookup key since it's typically unique and commonly
	// used for customer identification in auction systems.
	//
	// Parameters:
	//   - ctx: Context for request cancellation and timeout
	//   - email: Customer's email address to search for
	//
	// Returns:
	//   - *Customer: Customer entity if found, nil if not found
	//   - error: Database or lookup errors
	GetByEmail(ctx context.Context, email string) (*Customer, error)

	// Create persists a new customer entity to the data store
	// 
	// This method saves a new customer record to the database, typically used
	// when a new customer registers or is imported from external systems.
	// The customer ID should be pre-generated before calling this method.
	//
	// Parameters:
	//   - ctx: Context for request cancellation and timeout
	//   - customer: Customer entity to persist
	//
	// Returns:
	//   - error: Database persistence errors
	Create(ctx context.Context, customer *Customer) error

	// Update modifies an existing customer entity in the data store
	// 
	// This method updates an existing customer record with new information,
	// typically used when customer details change or are synchronized from
	// external systems. The UpdatedAt field should be set before calling.
	//
	// Parameters:
	//   - ctx: Context for request cancellation and timeout
	//   - customer: Customer entity with updated information
	//
	// Returns:
	//   - error: Database update errors
	Update(ctx context.Context, customer *Customer) error
}
