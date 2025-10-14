package offer_processing

import (
	"context"
	"fmt"

	billingDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/billing"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
	domainStrategy "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/strategy"
	orderInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/order"
)

type RegularAuctionStrategy struct {
	orderRepo orderInfrastructure.OrderRepository
}

func NewRegularAuctionStrategy(
	orderRepo orderInfrastructure.OrderRepository,
) *RegularAuctionStrategy {
	return &RegularAuctionStrategy{
		orderRepo: orderRepo,
	}
}

func (s *RegularAuctionStrategy) ProcessApprovedOrders(
	ctx context.Context,
	orders []*orderDomain.Order,
	billing *billingDomain.Billing,
	state string,
) (*domainStrategy.OfferProcessingResult, error) {

	result := &domainStrategy.OfferProcessingResult{
		ItemNames:   []string{},
		TotalAmount: 0,
	}

	for _, order := range orders {
		if result.CustomerEmail == "" && len(orders) > 0 {
			result.CustomerEmail = orders[0].CustomerId
		}

		switch state {
		case "Approved":
			order.State = "Pending"
		case "Rejected", "Error":
			order.State = "Rejected"
		default:
			continue
		}

		err := s.orderRepo.UpdateOrder(ctx, order)
		if err != nil {
			return nil, fmt.Errorf("no se pudo actualizar la orden %s: %v", order.OrderId, err)
		}

		result.ItemNames = append(result.ItemNames, order.ExtraData)
		result.TotalAmount += int64(order.OfferedAmount)
		result.ProcessedOrders++
	}

	return result, nil
}

func (s *RegularAuctionStrategy) GetOfferType() string {
	return "regular_auction"
}
