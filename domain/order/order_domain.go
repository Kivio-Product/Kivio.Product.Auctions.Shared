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

// GenerateCreatedState sets the order state to "Created" and returns the modified order
// 
// This function initializes a newly created order with the appropriate
// created state. It ensures that newly created order entities are
// immediately available for processing in the system.
//
// Parameters:
//   - order: Pointer to the order entity to modify
//
// Returns:
//   - *Order: Modified order with state set to "Created"
//
// Side Effects:
//   - Modifies the state field of the input entity
//
// Technical Details:
//   - Sets state to StateCreated constant ("Created")
//   - Returns the same pointer for method chaining
//   - Used during order creation workflow
func GenerateCreatedState(order *Order) *Order {
	order.State = StateCreated
	return order
}

// IsMultipleItems checks if the order contains multiple items
// 
// This method determines whether an order contains multiple items by checking
// if the Items slice has any elements. It provides a clean way to distinguish
// between single-item and multi-item orders throughout the system.
//
// Returns:
//   - bool: True if the order contains multiple items, false otherwise
//
// Side Effects:
//   - None (pure function)
//
// Technical Details:
//   - Checks if len(o.Items) > 0
//   - Returns false for single-item orders (Items slice is empty)
//   - Returns true for multi-item orders (Items slice has elements)
func (o *Order) IsMultipleItems() bool {
	return len(o.Items) > 0
}

// CalculateTotalAmount calculates the total amount for the order, handling both single and multiple item orders
// 
// This method computes the total monetary value of the order by handling different
// order types. For single-item orders, it returns the OfferedAmount directly.
// For multi-item orders, it calculates the sum of all item amounts (unit amount × quantity).
//
// Returns:
//   - int64: Total amount in the order's base currency units
//
// Side Effects:
//   - None (pure function)
//
// Technical Details:
//   - For single-item orders: returns o.OfferedAmount
//   - For multi-item orders: sums UnitAmount × Quantity for all items
//   - Uses int64 for monetary calculations to avoid floating-point precision issues
//   - Handles both order types seamlessly
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

// GetItemCount returns the total number of items in the order
// 
// This method calculates the total quantity of items in the order by handling
// different order types. For single-item orders, it returns 1. For multi-item
// orders, it sums the quantities of all items in the order.
//
// Returns:
//   - int: Total number of items in the order
//
// Side Effects:
//   - None (pure function)
//
// Technical Details:
//   - For single-item orders: returns 1
//   - For multi-item orders: sums Quantity field for all items
//   - Provides consistent item counting across order types
//   - Used for inventory and availability calculations
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

// Update modifies the order properties with new values, validating required fields
// 
// This method updates the order entity with new information while ensuring
// all required fields are properly validated. It performs comprehensive validation
// before applying any changes to the entity properties.
//
// Parameters:
//   - customerId: Unique identifier of the customer
//   - externalId: External system identifier for the order
//   - itemSpecificationId: Unique identifier of the item specification
//   - state: Current state of the order
//   - offeredAmount: Monetary amount offered for the order
//   - isWinner: Boolean indicating if the order is a winner
//
// Returns:
//   - error: Returns error if validation fails for any required field
//
// Side Effects:
//   - Modifies entity properties: CustomerId, ExternalId, ItemSpecificationId, OfferedAmount, State, SortKey, IsWinner
//
// Technical Details:
//   - Validates all parameters are non-empty/non-zero
//   - Returns specific error messages for each validation failure
//   - Updates entity fields only after successful validation
//   - Sets SortKey to "ACTIVE" for active orders
//   - Uses Spanish error messages for user-facing validation
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
