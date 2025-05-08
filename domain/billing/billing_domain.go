package domain

import (
	"errors"
	"time"
)

type Billing struct {
	Id            string    `json:"id" dynamodbav:"id"`
	TransactionId string    `json:"transactionId" dynamodbav:"transactionId"`
	State         string    `json:"state" dynamodbav:"state"`
	CreatedAt     time.Time `json:"createdAt" dynamodbav:"createdAt"`
	Provider      string    `json:"provider" dynamodbav:"provider"`
	PayloadType   string    `json:"payloadType" dynamodbav:"payloadType"`
	ConfirmedAt   time.Time `json:"confirmedAt" dynamodbav:"confirmedAt"`
	CustomerId    *string   `json:"customerId" dynamodbav:"customerId"`
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

type BillOrder struct {
	OfferId         string `json:"offer_id"`
	ItemName        string `json:"item_name"`
	ItemDescription string `json:"item_description"`
	OrderAmount     int64  `json:"order_amount"`
	ItemPrice       int64  `json:"item_price"`
}

type BillingRepositoryResult struct {
	Billings   []BillingByOrder `json:"billings"`
	NextToken  string           `json:"nextToken,omitempty"`
	TotalCount int64            `json:"totalCount"`
}

type PaginatedBillingDetailsResponse struct {
	Billings   []BillingDetailResponse `json:"items"`
	NextToken  string                  `json:"nextToken"`
	TotalCount int64                   `json:"totalCount"`
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
