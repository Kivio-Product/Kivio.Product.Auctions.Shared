package strategy

import (
	"context"

	billingDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/billing"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
)

type OfferProcessingResult struct {
	ItemNames        []string
	TotalAmount      int64
	CustomerEmail    string
	ProcessedOrders  int
	ShouldCloseOffer bool
	OfferID          string
}

type OfferProcessingStrategy interface {
	ProcessApprovedOrders(
		ctx context.Context,
		orders []*orderDomain.Order,
		billing *billingDomain.Billing,
		state string,
	) (*OfferProcessingResult, error)

	GetOfferType() string
}
