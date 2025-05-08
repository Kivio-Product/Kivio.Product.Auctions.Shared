package domain

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

type BillingFactory interface {
	CreateBilling(payloadType string) (*Billing, error)
}

type DefaultBillingFactory struct{}

func NewBillingFactory() BillingFactory {
	return &DefaultBillingFactory{}
}

func (f *DefaultBillingFactory) CreateBilling(provider string) (*Billing, error) {
	if provider == "" {
		return nil, fmt.Errorf("provider no puede estar vacío")
	}

	return &Billing{
		Id:            generateUUID(),
		State:         "Pending",
		Provider:      provider,
		CreatedAt:     time.Now(),
		TransactionId: "",
		PayloadType:   "",
		ConfirmedAt:   time.Time{},
	}, nil
}

func generateUUID() string {
	return uuid.New().String()
}
