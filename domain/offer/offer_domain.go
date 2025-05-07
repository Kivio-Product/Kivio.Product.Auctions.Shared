package domain

import (
	"errors"
	"time"
)

type Offer struct {
	OfferId     string
	CreatedAt   time.Time
	Description string
	Name        string
	PosId       string
	State       string
	Type        string
	AuctionTime int64
	SortKey     string
}

var (
	StateInactive = "Created"
	StateActive   = "Offered"
)

func (o *Offer) Update(name, description string, auctionTime int64) error {
	if name == "" {
		return errors.New("El nombre no puede estar vacío")
	}
	if description == "" {
		return errors.New("La descripcion no puede estar vacía")
	}
	if auctionTime < 0 {
		return errors.New("el auctionTime debe ser mayor a cero")
	}
	o.Name = name
	o.Description = description
	o.AuctionTime = auctionTime
	o.SortKey = "ACTIVE"
	return nil
}

func (o *Offer) UpdateState(state string) error {
	if state == "" {
		return errors.New("El estado no puede estar vacío")
	}
	o.State = state
	return nil
}
