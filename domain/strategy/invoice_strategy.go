package strategy

import (
	"context"

	billingDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/billing"
	invoiceDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/invoice"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
)

// InvoiceStrategy define la interfaz para crear facturas/ordenes en diferentes sistemas
// Puede ser Siigo (local), Ecommerce Order, u otros sistemas de facturación
type InvoiceStrategy interface {
	// CreateInvoiceForOrders crea una factura/orden para un conjunto de ordenes
	CreateInvoiceForOrders(
		ctx context.Context,
		billingID string,
		orders []*orderDomain.Order,
		customer *billingDomain.Customer,
		invoiceConfig *billingDomain.InvoiceConfig,
		posName string,
	) (*invoiceDomain.SiigoInvoiceResponse, error)

	// GetInvoiceType retorna el tipo de facturación (siigo, ecommerce, etc.)
	GetInvoiceType() string
}
