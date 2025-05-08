package domain

import (
	"errors"
	"time"
)

type Order struct {
	OrderId             string
	OfferId             string
	OfferedAmount       int64
	CreatedAt           time.Time
	CustomerId          string
	ExternalId          string
	ItemSpecificationId string
	State               string
}

type OrderDetail struct {
	OrderId         string    `json:"order_id"`
	ItemName        string    `json:"item_name"`
	ItemDescription string    `json:"item_description"`
	State           string    `json:"state"`
	CreatedAt       time.Time `json:"created_at"`
	CustomerId      string    `json:"customer_id"`
	ItemAmount      int64     `json:"item_amount"`
	OrderAmount     int64     `json:"order_amount"`
}

type PaginationParams struct {
	NextToken string `json:"nextToken"`
	PageSize  int    `json:"pageSize"`
	Search    string `json:"search"`
}
type OrderRepositoryResult struct {
	Orders     []Order `json:"orders"`
	NextToken  string  `json:"nextToken,omitempty"`
	TotalCount int64   `json:"totalCount"`
}

type PaginatedOrdersResponse struct {
	Orders     []OrderDetail `json:"items"`
	NextToken  string        `json:"nextToken,omitempty"`
	TotalCount int64         `json:"totalCount"`
}

type UpdateOrderStateRequest struct {
	State   string `json:"state"`
	OrderId string `json:"order_id"`
}

var (
	StateCreated = "Created"
	StateClosed  = "Closed"
)

func GenerateCreatedState(order *Order) *Order {
	order.State = StateCreated
	return order
}

func (o *Order) Update(customerId, externalId, itemSpecificationId, state string, offeredAmount int64) error {
	if customerId == "" {
		return errors.New("El customerId no puede estar vacío")
	}
	if externalId == "" {
		return errors.New("La externalId no puede estar vacía")
	}
	if itemSpecificationId == "" {
		return errors.New("La itemId no puede estar vacía")
	}
	if offeredAmount == 0 {
		return errors.New("La offeredAmount no puede estar vacía")
	}
	if state == "" {
		return errors.New("El state no puede estar vacía")
	}
	o.CustomerId = customerId
	o.ExternalId = externalId
	o.ItemSpecificationId = itemSpecificationId
	o.OfferedAmount = offeredAmount
	o.State = state
	return nil
}
