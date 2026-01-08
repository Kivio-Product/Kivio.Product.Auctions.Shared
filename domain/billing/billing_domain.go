package domain

import (
	"errors"
	"time"

	"github.com/aws/aws-sdk-go/service/dynamodb"
)

type Billing struct {
	Id              string         `json:"id" dynamodbav:"id"`
	TransactionId   string         `json:"transactionId" dynamodbav:"transactionId"`
	State           string         `json:"state" dynamodbav:"state"`
	CreatedAt       time.Time      `json:"createdAt" dynamodbav:"createdAt"`
	Provider        string         `json:"provider" dynamodbav:"provider"`
	PayloadType     string         `json:"payloadType" dynamodbav:"payloadType"`
	ConfirmedAt     time.Time      `json:"confirmedAt" dynamodbav:"confirmedAt"`
	CustomerId      *string        `json:"customerId" dynamodbav:"customerId"`
	UserId          string         `json:"userId" dynamodbav:"userId"`
	GaClienId       *string        `json:"gaClienId" dynamodbav:"gaClienId"`
	Customer        *Customer      `json:"customer" dynamodbav:"customer"`
	InvoiceConfig   *InvoiceConfig `json:"invoiceConfig" dynamodbav:"invoiceConfig"`
	PointOfSaleId   string         `json:"pos_id" dynamodbav:"posId"`
	SiigoInvoiceURL string         `json:"siigoInvoiceUrl,omitempty" dynamodbav:"siigoInvoiceUrl,omitempty"`
	ExternalId      string         `json:"externalId,omitempty" dynamodbav:"externalId,omitempty"`
}

type BillingResponse struct {
	Id            string `json:"id"`
	TransactionId string `json:"transaction_id"`
	State         string `json:"state"`
	Provider      string `json:"provider"`
	PayloadType   string `json:"payload_type"`
	CreatedAt     string `json:"created_at"`
	ConfirmedAt   string `json:"confirmed_at"`
}

type BillingDetailResponse struct {
	BillId          string      `json:"bill_id"`
	TransactionId   string      `json:"transaction_id"`
	State           string      `json:"state"`
	Provider        string      `json:"provider"`
	PayloadType     string      `json:"payload_type"`
	CreatedAt       time.Time   `json:"created_at"`
	ConfirmedAt     time.Time   `json:"confirmed_at"`
	UserEmail       string      `json:"user_email"`
	Orders          []BillOrder `json:"orders"`
	SiigoInvoiceURL string      `json:"siigo_invoice_url,omitempty"`
}

type BillOrder struct {
	OfferId         string `json:"offer_id"`
	ItemName        string `json:"item_name"`
	ItemDescription string `json:"item_description"`
	OrderAmount     int64  `json:"order_amount"`
	ItemPrice       int64  `json:"item_price"`
}

type BillingRepositoryResult struct {
	Billings   []Billing                           `json:"billings"`
	NextToken  map[string]*dynamodb.AttributeValue `json:"nextToken,omitempty"`
	TotalCount int64                               `json:"totalCount"`
}

type PaginatedBillingDetailsResponse struct {
	Billings   []BillingDetailResponse             `json:"items"`
	NextToken  map[string]*dynamodb.AttributeValue `json:"nextToken"`
	TotalCount int64                               `json:"totalCount"`
}

const (
	BillingStateApproved = "Approved"
	BillingStateFailed   = "Failed"
	BillingStatePending  = "Pending"
)

const (
	ProviderPayU   = "PAYU"
	ProviderStripe = "STRIPE"
	ProviderPaypal = "PAYPAL"
)

func (b *Billing) Update(state string) error {
	if state == "" {
		return errors.New("el estado no puede estar vacío")
	}
	b.State = state
	return nil
}

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

type CustomerAddress struct {
	Address    string       `json:"address" dynamodbav:"address"`
	City       CustomerCity `json:"city" dynamodbav:"city"`
	PostalCode string       `json:"postalCode" dynamodbav:"postalCode"`
}

type CustomerCity struct {
	CountryCode string `json:"countryCode" dynamodbav:"countryCode"`
	CountryName string `json:"countryName" dynamodbav:"countryName"`
	StateCode   string `json:"stateCode" dynamodbav:"stateCode"`
	StateName   string `json:"stateName" dynamodbav:"stateName"`
	CityCode    string `json:"cityCode" dynamodbav:"cityCode"`
	CityName    string `json:"cityName" dynamodbav:"cityName"`
}

type CustomerPhone struct {
	Indicative string `json:"indicative" dynamodbav:"indicative"`
	Number     string `json:"number" dynamodbav:"number"`
	Extension  string `json:"extension" dynamodbav:"extension"`
}

type CustomerContact struct {
	FirstName string        `json:"firstName" dynamodbav:"firstName"`
	LastName  string        `json:"lastName" dynamodbav:"lastName"`
	Email     string        `json:"email" dynamodbav:"email"`
	Phone     CustomerPhone `json:"phone" dynamodbav:"phone"`
}

type InvoiceConfig struct {
	DocumentID int `json:"documentId" dynamodbav:"documentId"`
	SellerID   int `json:"sellerId" dynamodbav:"sellerId"`
	PaymentID  int `json:"paymentId" dynamodbav:"paymentId"`
	TaxID      int `json:"taxId" dynamodbav:"taxId"`
}
