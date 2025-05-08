package domain

import (
	"fmt"

	"github.com/google/uuid"
)

type ItemFactory interface {
	CreateItem(name, description, externalId, pointOfSaleId, url string) (*Item, error)
}

type DefaultItemFactory struct{}

func NewItemFactory() ItemFactory {
	return &DefaultItemFactory{}
}

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

func generateUUID() string {
	return uuid.New().String()
}
