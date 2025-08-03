package domain

import (
	"time"
)

type CustomerConfigFactory interface {
	CreateCustomerConfig(input CustomerConfigInput) (*CustomerConfig, error)
}

type customerConfigFactory struct{}

func NewCustomerConfigFactory() CustomerConfigFactory {
	return &customerConfigFactory{}
}

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
