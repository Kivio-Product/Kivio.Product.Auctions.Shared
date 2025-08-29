package domain

import (
	"errors"
	"time"

	"github.com/aws/aws-sdk-go/service/dynamodb"
)

type OrderItem struct {
	ItemSpecificationId string `json:"item_specification_id"`
	Quantity            int    `json:"quantity"`
	UnitAmount          int64  `json:"unit_amount"`
}

type Order struct {
	OrderId             string
	OfferId             string
	OfferedAmount       int64
	CreatedAt           time.Time
	CustomerId          string
	ExternalId          string
	BillingId           string
	ItemSpecificationId string
	Items               []OrderItem `json:"items,omitempty"`
	ExtraData           string
	State               string
	SortKey             string
	PointOfSaleId       string
	WompiIdPayment      string
	IsWinner            bool
	TotalQuantity       int
}

type OrderDetail struct {
	OrderId         string    `json:"order_id"`
	ItemName        string    `json:"item_name"`
	ItemDescription string    `json:"item_description"`
	State           string    `json:"state"`
	CreatedAt       time.Time `json:"created_at"`
	CustomerId      string    `json:"customer_id"`
	OrderAmount     int64     `json:"order_amount"`
	ExtraData       string    `json:"extra_data"`
}

type PaginationParams struct {
	NextToken     map[string]*dynamodb.AttributeValue `json:"nextToken"`
	PageSize      int                                 `json:"pageSize"`
	Search        string                              `json:"search"`
	PointOfSaleId string                              `json:"pointOfSaleId"`
}
type OrderRepositoryResult struct {
	Orders     []Order                             `json:"orders"`
	NextToken  map[string]*dynamodb.AttributeValue `json:"nextToken,omitempty"`
	TotalCount int64                               `json:"totalCount"`
}

type PaginatedOrdersResponse struct {
	Orders     []OrderDetail                       `json:"items"`
	NextToken  map[string]*dynamodb.AttributeValue `json:"nextToken,omitempty"`
	TotalCount int64                               `json:"totalCount"`
}

type UpdateOrderStateRequest struct {
	State   string `json:"state"`
	OrderId string `json:"order_id"`
}

type OrderInput struct {
	OrderId             string
	CustomerId          string
	ExternalId          string
	ItemSpecificationId string
	Items               []OrderItem `json:"items,omitempty"`
	OfferId             string
	PointOfSaleId       string
	BillingId           string
	ExtraData           string
	OfferedAmount       int64
	State               string
	WompiIdPayment      string
	IsWinner            bool
}

var (
	StateCreated = "Created"
	StateClosed  = "Closed"
)

func GenerateCreatedState(order *Order) *Order {
	order.State = StateCreated
	return order
}

func (o *Order) IsMultipleItems() bool {
	return len(o.Items) > 0
}

func (o *Order) CalculateTotalAmount() int64 {
	if !o.IsMultipleItems() {
		return o.OfferedAmount
	}

	var total int64
	for _, item := range o.Items {
		total += item.UnitAmount * int64(item.Quantity) // Assuming UnitAmount is the price per item
	}
	return total
}

func (o *Order) GetItemCount() int {
	if !o.IsMultipleItems() {
		return 1
	}

	count := 0
	for _, item := range o.Items {
		count += item.Quantity
	}
	return count
}

func (o *Order) Update(customerId, externalId, itemSpecificationId, state string, offeredAmount int64, isWinner bool) error {
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
	o.SortKey = "ACTIVE"
	o.IsWinner = isWinner
	return nil
}
