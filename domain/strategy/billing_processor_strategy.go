package strategy

import (
	"context"

	billingDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/billing"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
)

type BillingProcessorStrategy interface {
	ProcessApprovedPayment(ctx context.Context, billing *billingDomain.Billing, orders []*orderDomain.Order) error

	ProcessRejectedPayment(ctx context.Context, billing *billingDomain.Billing, orders []*orderDomain.Order) error

	GetProcessorType() string
}
