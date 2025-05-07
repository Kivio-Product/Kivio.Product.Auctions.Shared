package pointofsale

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

type PosFactory interface {
	CreatePointOfSale(description, name, userId string) (*PointOfSale, error)
}

type DefaultPosFactory struct{}

func NewPosFactory() PosFactory {
	return &DefaultPosFactory{}
}

func (f *DefaultPosFactory) CreatePointOfSale(description, name, userId string) (*PointOfSale, error) {
	if name == "" {
		return nil, fmt.Errorf("Name cannot be empty")
	}
	if description == "" {
		return nil, fmt.Errorf("Description cannot be empty")
	}
	if userId == "" {
		return nil, fmt.Errorf("UserId cannot be empty")
	}
	return &PointOfSale{
		PointOfSaleId: generateUUID(),
		CreateAt:      time.Now(),
		Description:   description,
		Name:          name,
		UserId:        userId,
	}, nil
}

func generateUUID() string {
	return uuid.New().String()
}
