package strategy

import (
	"context"

	billingDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/billing"
	invoiceDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/invoice"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
)

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
