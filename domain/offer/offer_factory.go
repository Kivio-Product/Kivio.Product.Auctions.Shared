package domain

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

type OfferFactory interface {
	CreateOffer(name, description, posId, typer string, auctionTime int64) (*Offer, error)
}

type DefaultOfferFactory struct{}

func NewOfferFactory() OfferFactory {
	return &DefaultOfferFactory{}
}

func (f *DefaultOfferFactory) CreateOffer(name, description, posId, typer string, auctionTime int64) (*Offer, error) {

	if name == "" {
		return nil, fmt.Errorf("Name cannot be empty")
	}
	if description == "" {
		return nil, fmt.Errorf("Description cannot be empty")
	}
	if posId == "" {
		return nil, fmt.Errorf("PointOfSaleId cannot be empty")
	}
	if typer == "" {
		return nil, fmt.Errorf("Type cannot be empty")
	}

	return &Offer{
		OfferId:     generateUUID(),
		Name:        name,
		Description: description,
		CreatedAt:   time.Now(),
		PosId:       posId,
		Type:        typer,
		AuctionTime: auctionTime,
		SortKey:     "ACTIVE",
	}, nil
}

func generateUUID() string {
	return uuid.New().String()
}
