package strategy

import (
	"context"

	billingDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/billing"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
)

// BillingProcessorStrategy define la interfaz para procesar diferentes tipos de billing
// Puede ser para Quick Offer, Regular Auction, etc.
type BillingProcessorStrategy interface {
	// ProcessApprovedPayment procesa un pago aprobado y ejecuta las acciones correspondientes
	ProcessApprovedPayment(ctx context.Context, billing *billingDomain.Billing, orders []*orderDomain.Order) error

	// ProcessRejectedPayment procesa un pago rechazado
	ProcessRejectedPayment(ctx context.Context, billing *billingDomain.Billing, orders []*orderDomain.Order) error

	// GetProcessorType retorna el tipo de procesador
	GetProcessorType() string
}
