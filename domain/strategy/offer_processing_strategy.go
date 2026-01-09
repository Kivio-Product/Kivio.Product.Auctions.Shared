package strategy

import (
	"context"

	billingDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/billing"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
)

// OfferProcessingResult contains the results of processing approved orders for an offer
//
// This struct encapsulates all the relevant information generated during the
// offer processing workflow, providing a comprehensive summary of the processing
// operation and its outcomes.
type OfferProcessingResult struct {
	// ItemNames contains the names of all items included in the processed orders
	// This list helps identify which products were part of the successful transaction
	ItemNames []string

	// TotalAmount represents the total monetary value of all processed orders
	// This value is typically in the smallest currency unit (e.g., cents for USD)
	TotalAmount int64

	// CustomerEmail is the email address of the customer who placed the orders
	// This is used for notifications and customer communication
	CustomerEmail string

	// ProcessedOrders indicates the number of orders that were successfully processed
	// This count helps track the volume of orders handled in this processing cycle
	ProcessedOrders int

	// ShouldCloseOffer indicates whether the offer should be closed after processing
	// This flag helps determine if the offer has reached its completion criteria
	ShouldCloseOffer bool

	// OfferID is the unique identifier of the offer being processed
	// This links the processing result back to the specific offer
	OfferID string
}

// OfferProcessingStrategy defines the contract for offer processing operations
//
// This interface abstracts offer processing operations, providing a clean contract
// for implementations that handle different offer processing strategies and workflows.
// It supports various offer types and processing rules through the strategy pattern.
//
// Implementations should handle:
//   - Order validation and processing workflows
//   - Offer completion criteria evaluation
//   - Customer notification and communication
//   - Integration with external systems and services
//
type OfferProcessingStrategy interface {
	// ProcessApprovedOrders processes a collection of approved orders for an offer
	//
	// This method handles the complete workflow of processing approved orders within
	// the context of an offer. It should handle:
	//   - Order validation and status updates
	//   - Inventory management and stock adjustments
	//   - Customer notification and communication
	//   - Offer completion evaluation and closure decisions
	//   - Integration with external systems (payment, fulfillment, etc.)
	//   - Error handling and rollback procedures
	//
	// Parameters:
	//   - ctx: Context for request cancellation and timeout handling
	//   - orders: Collection of approved orders to be processed
	//   - billing: Billing information associated with the orders
	//   - state: Current state of the offer processing workflow
	//
	// Returns:
	//   - *OfferProcessingResult: Comprehensive result of the processing operation
	//   - error: Any error encountered during processing
	ProcessApprovedOrders(
		ctx context.Context,
		orders []*orderDomain.Order,
		billing *billingDomain.Billing,
		state string,
	) (*OfferProcessingResult, error)

	// GetOfferType returns the type identifier for this offer processing strategy
	//
	// This method provides a unique identifier for the specific offer processing
	// implementation. This identifier is used for:
	//   - Strategy selection and routing
	//   - Logging and debugging purposes
	//   - Configuration and feature flagging
	//   - Monitoring and metrics collection
	//
	// Returns:
	//   - string: A unique identifier for this offer type (e.g., "auction", "flash_sale", "group_buy")
	GetOfferType() string
}
