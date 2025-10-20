package domain

import (
	"fmt"

	"github.com/google/uuid"
)

type ItemFactory interface {
	CreateItem(name, description, externalId, pointOfSaleId, url string) (*Item, error)
}

type DefaultItemFactory struct{}

// NewItemFactory creates a new instance of the default item factory
func NewItemFactory() ItemFactory {
	return &DefaultItemFactory{}
}

// CreateItem creates a new item instance with the provided details, validating required fields
func (f *DefaultItemFactory) CreateItem(name, description, externalId, pointOfSaleId, url string) (*Item, error) {

	if name == "" {
		return nil, fmt.Errorf("Name cannot be empty")
	}
	if description == "" {
		return nil, fmt.Errorf("Description cannot be empty")
	}
	if pointOfSaleId == "" {
		return nil, fmt.Errorf("PointOfSaleId cannot be empty")
	}
	return &Item{
		ItemId:        generateUUID(),
		Name:          name,
		Description:   description,
		ExternalId:    externalId,
		PointOfSaleId: pointOfSaleId,
		Url:           url,
	}, nil
}

// generateUUID generates a new UUID string for item identification
func generateUUID() string {
	return uuid.New().String()
}
