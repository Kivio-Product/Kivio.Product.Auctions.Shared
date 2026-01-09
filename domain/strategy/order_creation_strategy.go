package strategy

import (
	"context"

	billingDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/billing"
	itemDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
	itemSpecDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item_specification"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
)

// OrderCreationStrategy defines the contract for order creation and management operations
//
// This interface abstracts order creation operations, providing a clean contract
// for implementations that handle different order creation strategies and workflows.
// It supports various order types and external system integrations through the strategy pattern.
//
// Implementations should handle:
//   - External order creation and synchronization
//   - Order finalization and completion workflows
//   - Integration with external commerce platforms
//   - Order status management and tracking
//
type OrderCreationStrategy interface {
	// CreateExternalOrder creates an order in an external system
	//
	// This method handles the creation of an order in an external commerce platform
	// or system. It should handle:
	//   - External system authentication and authorization
	//   - Order data transformation and mapping
	//   - External API calls and error handling
	//   - Order validation and confirmation
	//   - Integration-specific business rules and constraints
	//
	// Parameters:
	//   - ctx: Context for request cancellation and timeout handling
	//   - billing: Billing information associated with the order
	//   - order: The order to be created in the external system
	//   - item: The item details for the order
	//   - itemSpec: Item specification details for the order
	//
	// Returns:
	//   - error: Any error encountered during external order creation
	CreateExternalOrder(
		ctx context.Context,
		billing *billingDomain.Billing,
		order *orderDomain.Order,
		item *itemDomain.Item,
		itemSpec *itemSpecDomain.ItemSpecification,
	) error

	// FinalizeOrder completes the order processing workflow
	//
	// This method handles the finalization of orders after they have been created
	// and processed. It should handle:
	//   - Order status updates to completed/finalized
	//   - Final validation and confirmation steps
	//   - Integration with fulfillment systems
	//   - Customer notification and communication
	//   - Post-order processing workflows
	//   - Error handling and rollback procedures
	//
	// Parameters:
	//   - ctx: Context for request cancellation and timeout handling
	//   - billing: Billing information associated with the orders
	//   - orders: Collection of orders to be finalized
	//
	// Returns:
	//   - error: Any error encountered during order finalization
	FinalizeOrder(
		ctx context.Context,
		billing *billingDomain.Billing,
		orders []*orderDomain.Order,
	) (invoiceURL string, externalOrderID string, err error)

	// GetOrderType returns the type identifier for this order creation strategy
	//
	// This method provides a unique identifier for the specific order creation
	// implementation. This identifier is used for:
	//   - Strategy selection and routing
	//   - Logging and debugging purposes
	//   - Configuration and feature flagging
	//   - Monitoring and metrics collection
	//
	// Returns:
	//   - string: A unique identifier for this order type (e.g., "ecommerce", "pos", "marketplace")
	GetOrderType() string
}
