package strategy

import (
	"context"

	billingDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/billing"
	invoiceDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/invoice"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
)

// InvoiceStrategy defines the contract for invoice creation operations
// 
// This interface abstracts invoice creation operations, providing a clean contract
// for implementations that handle different invoice generation strategies.
// It supports various invoice systems and formats through the strategy pattern.
//
// Implementations should handle:
//   - Invoice creation for order collections
//   - Integration with external invoice systems (e.g., Siigo)
//   - Customer and configuration data processing
//   - Error handling and validation
//
type InvoiceStrategy interface {
	CreateInvoiceForOrders(
		ctx context.Context,
		billingID string,
		orders []*orderDomain.Order,
		customer *billingDomain.Customer,
		invoiceConfig *billingDomain.InvoiceConfig,
		posName string,
	) (*invoiceDomain.SiigoInvoiceResponse, error)

	GetInvoiceType() string
}
