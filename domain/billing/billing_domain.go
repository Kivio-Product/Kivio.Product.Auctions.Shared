package domain

import (
	"errors"
	"time"

	"github.com/aws/aws-sdk-go/service/dynamodb"
)

// Billing represents a payment transaction in the auction system
// 
// A Billing entity tracks the complete lifecycle of a payment transaction,
// including its state, provider, customer information, and invoice configuration.
// It serves as the central record for payment processing and confirmation.
type Billing struct {
	Id            string         `json:"id" dynamodbav:"id"`
	TransactionId string         `json:"transactionId" dynamodbav:"transactionId"`
	State         string         `json:"state" dynamodbav:"state"`
	CreatedAt     time.Time      `json:"createdAt" dynamodbav:"createdAt"`
	Provider      string         `json:"provider" dynamodbav:"provider"`
	PayloadType   string         `json:"payloadType" dynamodbav:"payloadType"`
	ConfirmedAt   time.Time      `json:"confirmedAt" dynamodbav:"confirmedAt"`
	CustomerId    *string        `json:"customerId" dynamodbav:"customerId"`
	Customer      *Customer      `json:"customer" dynamodbav:"customer"`
	InvoiceConfig *InvoiceConfig `json:"invoiceConfig" dynamodbav:"invoiceConfig"`
	PointOfSaleId string         `json:"pos_id" dynamodbav:"posId"`
}

// BillingResponse represents a simplified billing response for API consumers
// 
// This struct provides a clean, API-friendly representation of billing information
// with string-formatted timestamps and standardized field names for external consumption.
type BillingResponse struct {
	Id            string `json:"id"`
	TransactionId string `json:"transaction_id"`
	State         string `json:"state"`
	Provider      string `json:"provider"`
	PayloadType   string `json:"payload_type"`
	CreatedAt     string `json:"created_at"`
	ConfirmedAt   string `json:"confirmed_at"`
}

// BillingDetailResponse represents detailed billing information including customer and order details
// 
// This struct provides comprehensive billing information for detailed views,
// including customer email and associated orders for complete transaction context.
type BillingDetailResponse struct {
	BillId        string      `json:"bill_id"`
	TransactionId string      `json:"transaction_id"`
	State         string      `json:"state"`
	Provider      string      `json:"provider"`
	PayloadType   string      `json:"payload_type"`
	CreatedAt     time.Time   `json:"created_at"`
	ConfirmedAt   time.Time   `json:"confirmed_at"`
	UserEmail     string      `json:"user_email"`
	Orders        []BillOrder `json:"orders"`
}

// BillOrder represents an order within a billing transaction
// 
// This struct contains the essential order information that appears in billing
// details, providing context about what items were purchased in the transaction.
type BillOrder struct {
	OfferId         string `json:"offer_id"`
	ItemName        string `json:"item_name"`
	ItemDescription string `json:"item_description"`
	OrderAmount     int64  `json:"order_amount"`
	ItemPrice       int64  `json:"item_price"`
}

// BillingRepositoryResult represents paginated billing query results
// 
// This struct encapsulates the results of paginated billing queries,
// including the billing records, pagination token, and total count for
// efficient data retrieval and pagination handling.
type BillingRepositoryResult struct {
	Billings   []Billing                           `json:"billings"`
	NextToken  map[string]*dynamodb.AttributeValue `json:"nextToken,omitempty"`
	TotalCount int64                               `json:"totalCount"`
}

// PaginatedBillingDetailsResponse represents paginated detailed billing information
// 
// This struct provides paginated access to detailed billing information,
// combining billing details with pagination metadata for efficient data browsing.
type PaginatedBillingDetailsResponse struct {
	Billings   []BillingDetailResponse             `json:"items"`
	NextToken  map[string]*dynamodb.AttributeValue `json:"nextToken"`
	TotalCount int64                               `json:"totalCount"`
}

// Predefined billing states for payment lifecycle management
const (
	BillingStateApproved = "Approved"
	BillingStateFailed   = "Failed"
	BillingStatePending  = "Pending"
)

// Predefined payment providers supported by the system
const (
	ProviderPayU   = "PAYU"
	ProviderStripe = "STRIPE"
	ProviderPaypal = "PAYPAL"
)

// Update changes the current state of the billing transaction
// 
// This method allows updating the payment state of a billing transaction,
// typically used when payment status changes (e.g., from Pending to Approved or Failed).
// It performs basic validation to ensure the state is not empty.
//
// Parameters:
//   - state: The new payment state to set (must not be empty)
//
// Returns:
//   - error: Returns an error if the state parameter is empty
//
// Side Effects:
//   - Modifies the billing's State field
//   - No validation is performed on the state value itself
//
// Business Rules:
//   - State cannot be empty (validates input)
//   - No restrictions on which states can transition to which other states
//   - State changes are immediate and don't trigger additional business logic
func (b *Billing) Update(state string) error {
	if state == "" {
		return errors.New("el estado no puede estar vacío")
	}
	b.State = state
	return nil
}

// Customer represents customer information for billing purposes
// 
// This struct contains comprehensive customer data required for payment processing,
// including personal information, addresses, and contact details needed for
// invoice generation and payment provider requirements.
type Customer struct {
	ID              string            `json:"id" dynamodbav:"id"`
	Email           string            `json:"email" dynamodbav:"email"`
	PersonType      string            `json:"personType" dynamodbav:"personType"`
	IDType          string            `json:"idType" dynamodbav:"idType"`
	Identification  string            `json:"identification" dynamodbav:"identification"`
	Name            []string          `json:"name" dynamodbav:"name"`
	Address         CustomerAddress   `json:"address" dynamodbav:"address"`
	ShippingAddress *CustomerAddress  `json:"shippingAddress,omitempty" dynamodbav:"shippingAddress,omitempty"`
	Phones          []CustomerPhone   `json:"phones" dynamodbav:"phones"`
	Contacts        []CustomerContact `json:"contacts" dynamodbav:"contacts"`
	CreatedAt       time.Time         `json:"createdAt" dynamodbav:"createdAt"`
	UpdatedAt       time.Time         `json:"updatedAt" dynamodbav:"updatedAt"`
}

// CustomerAddress represents a customer's address information
// 
// This struct contains detailed address information including street address,
// city details, and postal code for billing and shipping purposes.
type CustomerAddress struct {
	Address    string       `json:"address" dynamodbav:"address"`
	City       CustomerCity `json:"city" dynamodbav:"city"`
	PostalCode string       `json:"postalCode" dynamodbav:"postalCode"`
}

// CustomerCity represents detailed city information for address purposes
// 
// This struct contains comprehensive geographic information including country,
// state, and city details with both codes and names for complete location data.
type CustomerCity struct {
	CountryCode string `json:"countryCode" dynamodbav:"countryCode"`
	CountryName string `json:"countryName" dynamodbav:"countryName"`
	StateCode   string `json:"stateCode" dynamodbav:"stateCode"`
	StateName   string `json:"stateName" dynamodbav:"stateName"`
	CityCode    string `json:"cityCode" dynamodbav:"cityCode"`
	CityName    string `json:"cityName" dynamodbav:"cityName"`
}

// CustomerPhone represents a customer's phone number information
// 
// This struct contains phone number details including country code,
// phone number, and optional extension for contact purposes.
type CustomerPhone struct {
	Indicative string `json:"indicative" dynamodbav:"indicative"`
	Number     string `json:"number" dynamodbav:"number"`
	Extension  string `json:"extension" dynamodbav:"extension"`
}

// CustomerContact represents additional contact information for a customer
// 
// This struct contains contact person details including name, email,
// and phone information for additional communication purposes.
type CustomerContact struct {
	FirstName string        `json:"firstName" dynamodbav:"firstName"`
	LastName  string        `json:"lastName" dynamodbav:"lastName"`
	Email     string        `json:"email" dynamodbav:"email"`
	Phone     CustomerPhone `json:"phone" dynamodbav:"phone"`
}

// InvoiceConfig represents invoice configuration for billing purposes
// 
// This struct contains the necessary configuration IDs for invoice generation,
// including document, seller, payment, and tax identifiers required by
// external invoice systems or payment providers.
type InvoiceConfig struct {
	DocumentID int `json:"documentId" dynamodbav:"documentId"`
	SellerID   int `json:"sellerId" dynamodbav:"sellerId"`
	PaymentID  int `json:"paymentId" dynamodbav:"paymentId"`
	TaxID      int `json:"taxId" dynamodbav:"taxId"`
}
