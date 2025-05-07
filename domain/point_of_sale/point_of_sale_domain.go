package pointofsale

import (
	"errors"
	"time"
)

type PointOfSale struct {
	PointOfSaleId string
	CreateAt      time.Time
	Description   string
	Name          string
	State         string
	UserId        string
}

var (
	StateInactive = "Inactive"
	StateActive   = "Active"
)

func GenerateCreatedState(pos *PointOfSale) *PointOfSale {
	pos.State = StateActive
	return pos
}

func (o *PointOfSale) Update(name, description, pointOfSaleId, userId string) error {
	if name == "" {
		return errors.New("El nombre no puede estar vacío")
	}
	if description == "" {
		return errors.New("La descripcion no puede estar vacía")
	}
	if pointOfSaleId == "" {
		return errors.New("El punto de venta no puede estar vacío")
	}
	if userId == "" {
		return errors.New("El userId no puede estar vacío")
	}
	o.Name = name
	o.Description = description
	o.PointOfSaleId = pointOfSaleId
	o.UserId = userId
	return nil
}
