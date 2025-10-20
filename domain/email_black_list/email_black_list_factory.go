package domain

import (
	"fmt"
)

// EmailBlackListFactory defines the contract for creating new EmailBlackList instances
// 
// The factory pattern is used here to encapsulate the creation logic of EmailBlackList
// entities, ensuring proper validation and initialization. This interface allows for
// different implementations of email blacklist creation strategies.
type EmailBlackListFactory interface {
	Create(email string) (*EmailBlackList, error)
}

// DefaultEmailBlackListFactory provides the standard implementation of EmailBlackListFactory
// 
// This concrete implementation handles the creation of EmailBlackList entities with
// standard business rules and validation. It performs basic email validation
// to ensure only valid email addresses are blacklisted.
type DefaultEmailBlackListFactory struct{}

// NewEmailBlackListFactory creates a new instance of the default email blacklist factory
// 
// This constructor function returns a concrete implementation of the EmailBlackListFactory
// interface. It follows the factory pattern by providing a clean way to instantiate
// the factory without exposing implementation details.
//
// Returns:
//   - EmailBlackListFactory: A new instance of DefaultEmailBlackListFactory implementing the interface
func NewEmailBlackListFactory() EmailBlackListFactory {
	return &DefaultEmailBlackListFactory{}
}

// Create creates a new EmailBlackList instance with validation
// 
// This method is the core factory method that creates new EmailBlackList entities
// following the domain's business rules. It performs basic validation to ensure
// the email address is not empty before creating the blacklist entry.
//
// Parameters:
//   - email: The email address to blacklist (must not be empty)
//
// Returns:
//   - *EmailBlackList: A new EmailBlackList instance with the provided email
//   - error: Validation errors if the email parameter is empty
//
// Side Effects:
//   - None (pure creation method)
//
// Business Rules:
//   - Email cannot be empty (basic validation)
//   - No email format validation is performed (only non-empty check)
//   - Creates simple blacklist entry with provided email
func (f *DefaultEmailBlackListFactory) Create(email string) (*EmailBlackList, error) {

	if email == "" {
		return nil, fmt.Errorf("Email cannot be empty")
	}

	return &EmailBlackList{
		Email: email,
	}, nil
}
