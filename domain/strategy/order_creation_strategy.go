package strategy

import (
	"context"

	billingDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/billing"
	itemDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
	itemSpecDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item_specification"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
)

type OrderCreationStrategy interface {
	CreateExternalOrder(
		ctx context.Context,
		billing *billingDomain.Billing,
		order *orderDomain.Order,
		item *itemDomain.Item,
		itemSpec *itemSpecDomain.ItemSpecification,
	) error

	FinalizeOrder(
		ctx context.Context,
		billing *billingDomain.Billing,
		orders []*orderDomain.Order,
	) (invoiceURL string, externalOrderID string, err error)

	GetOrderType() string
}
