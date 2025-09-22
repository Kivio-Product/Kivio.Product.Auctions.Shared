package domain

import (
	"context"
	"time"
)

type Customer struct {
	ID                 string    `json:"id" dynamodbav:"id"`
	Email              string    `json:"email" dynamodbav:"email"`
	ExternalCustomerID string    `json:"externalCustomerId" dynamodbav:"externalCustomerId"`
	BillingAddressID   string    `json:"billingAddressId" dynamodbav:"billingAddressId"`
	CreatedAt          time.Time `json:"createdAt" dynamodbav:"createdAt"`
	UpdatedAt          time.Time `json:"updatedAt" dynamodbav:"updatedAt"`
}

type CustomerRepository interface {
	GetByEmail(ctx context.Context, email string) (*Customer, error)
	Create(ctx context.Context, customer *Customer) error
	Update(ctx context.Context, customer *Customer) error
}
