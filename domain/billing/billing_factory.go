package domain

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

type BillingFactory interface {
	CreateBilling(provider string, customer *Customer, invoiceConfig *InvoiceConfig) (*Billing, error)
}

type DefaultBillingFactory struct{}

func NewBillingFactory() BillingFactory {
	return &DefaultBillingFactory{}
}

func (f *DefaultBillingFactory) CreateBilling(provider string, customer *Customer, invoiceConfig *InvoiceConfig) (*Billing, error) {
	if provider == "" {
		return nil, fmt.Errorf("provider no puede estar vacío")
	}
	if customer == nil {
		return nil, fmt.Errorf("customer no puede estar vacío")
	}
	if invoiceConfig == nil {
		return nil, fmt.Errorf("invoiceConfig no puede estar vacío")
	}

	return &Billing{
		Id:            generateUUID(),
		State:         "Pending",
		Provider:      provider,
		CreatedAt:     time.Now(),
		TransactionId: "",
		PayloadType:   "",
		ConfirmedAt:   time.Time{},
		Customer:      customer,
		InvoiceConfig: invoiceConfig,
	}, nil
}

func generateUUID() string {
	return uuid.New().String()
}
