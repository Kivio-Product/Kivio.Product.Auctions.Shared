package domain

import (
	"errors"
	"time"
)

type CustomerConfig struct {
	CustomerID         string    `json:"customer_id"`
	AllowMultipleItems bool      `json:"allow_multiple_items"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
	PointOfSaleId      string    `json:"point_of_sale_id"`
}

type CustomerConfigInput struct {
	CustomerID         string `json:"customer_id"`
	AllowMultipleItems bool   `json:"allow_multiple_items"`
	PointOfSaleId      string `json:"point_of_sale_id"`
}

type CustomerConfigRepository interface {
	GetByCustomerID(customerID string) (*CustomerConfig, error)
	Save(config *CustomerConfig) error
	Update(config *CustomerConfig) error
	Delete(customerID string) error
}

func (c *CustomerConfig) Update(allowMultipleItems bool) error {
	c.AllowMultipleItems = allowMultipleItems
	c.UpdatedAt = time.Now()
	return nil
}

func (c *CustomerConfig) Validate() error {
	if c.CustomerID == "" {
		return errors.New("customer_id cannot be empty")
	}
	if c.PointOfSaleId == "" {
		return errors.New("point_of_sale_id cannot be empty")
	}
	return nil
}
