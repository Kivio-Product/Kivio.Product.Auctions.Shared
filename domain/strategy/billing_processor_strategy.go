package strategy

import (
	"context"

	billingDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/billing"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
)

// BillingProcessorStrategy defines the contract for billing payment processing operations
//
// This interface abstracts billing payment processing operations, providing a clean contract
// for implementations that handle different payment processing strategies.
// It supports various payment processors and workflows through the strategy pattern.
//
// Implementations should handle:
//   - Approved payment processing workflows
//   - Rejected payment handling and rollback operations
//   - Integration with external payment systems
//   - Order status updates and notifications
//
type BillingProcessorStrategy interface {
	// ProcessApprovedPayment handles the processing of approved payments
	//
	// This method is called when a payment has been successfully approved by the payment processor.
	// It should handle the completion of the billing process, including:
	//   - Updating order statuses to reflect successful payment
	//   - Triggering any post-payment workflows (invoicing, fulfillment, etc.)
	//   - Sending confirmation notifications to customers
	//   - Recording payment completion in the system
	//
	// Parameters:
	//   - ctx: Context for request cancellation and timeout handling
	//   - billing: The billing record containing payment details
	//   - orders: Collection of orders associated with this payment
	//
	// Returns:
	//   - error: Any error encountered during payment processing
	ProcessApprovedPayment(ctx context.Context, billing *billingDomain.Billing, orders []*orderDomain.Order) error

	// ProcessRejectedPayment handles the processing of rejected payments
	//
	// This method is called when a payment has been rejected by the payment processor.
	// It should handle the rollback of the billing process, including:
	//   - Reverting order statuses to reflect payment failure
	//   - Restoring item stock levels if applicable
	//   - Triggering any cleanup workflows
	//   - Sending failure notifications to customers
	//   - Recording payment failure in the system
	//
	// Parameters:
	//   - ctx: Context for request cancellation and timeout handling
	//   - billing: The billing record containing payment details
	//   - orders: Collection of orders associated with this payment
	//
	// Returns:
	//   - error: Any error encountered during payment rejection processing
	ProcessRejectedPayment(ctx context.Context, billing *billingDomain.Billing, orders []*orderDomain.Order) error

	// GetProcessorType returns the type identifier for this billing processor strategy
	//
	// This method provides a unique identifier for the specific billing processor
	// implementation. This identifier is used for:
	//   - Strategy selection and routing
	//   - Logging and debugging purposes
	//   - Configuration and feature flagging
	//   - Monitoring and metrics collection
	//
	// Returns:
	//   - string: A unique identifier for this processor type (e.g., "wompi", "payu", "stripe")
	GetProcessorType() string
}
