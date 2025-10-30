package offer_processing

import (
	"context"
	"fmt"

	strategyApp "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/strategy"
	billingDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/billing"
	itemDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
	domainStrategy "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/strategy"
	itemSpecInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/item_specification"
)

type RegularAuctionStrategy struct {
	itemSpecRepo         itemSpecInfrastructure.ItemSpecificationRepository
	itemSourceFactory    *strategyApp.ItemSourceFactory
	orderCreationFactory *strategyApp.OrderCreationStrategyFactory
}

func NewRegularAuctionStrategy(
	itemSpecRepo itemSpecInfrastructure.ItemSpecificationRepository,
	itemSourceFactory *strategyApp.ItemSourceFactory,
	orderCreationFactory *strategyApp.OrderCreationStrategyFactory,
) *RegularAuctionStrategy {
	return &RegularAuctionStrategy{
		itemSpecRepo:         itemSpecRepo,
		itemSourceFactory:    itemSourceFactory,
		orderCreationFactory: orderCreationFactory,
	}
}

func (s *RegularAuctionStrategy) ProcessApprovedOrders(
	ctx context.Context,
	orders []*orderDomain.Order,
	billing *billingDomain.Billing,
	state string,
) (*domainStrategy.OfferProcessingResult, error) {

	fmt.Printf("[RegularAuction] Processing payment confirmation for %d orders\n", len(orders))
	fmt.Printf("[RegularAuction] Note: Order states and ItemSpec availability were already updated by ProcessOffer\n")

	result := &domainStrategy.OfferProcessingResult{
		ItemNames:   []string{},
		TotalAmount: 0,
	}

	ordersBySource := make(map[string][]*orderDomain.Order)

	for _, order := range orders {
		itemSpec, err := s.itemSpecRepo.GetById(ctx, order.ItemSpecificationId)
		if err != nil {
			fmt.Printf("[RegularAuction] No se encontró el itemSpec con Id: %s\n", order.ItemSpecificationId)
			continue
		}

		result.ItemNames = append(result.ItemNames, order.ExtraData)
		result.TotalAmount += int64(order.OfferedAmount)

		if result.CustomerEmail == "" {
			result.CustomerEmail = order.CustomerId
		}

		if state == "Approved" && order.State == "Approved" && itemSpec.GetSource() != "" {
			var item *itemDomain.Item
			itemSourceStrategy, err := s.itemSourceFactory.GetStrategyByItemSpec(ctx, string(itemSpec.GetSource()), order.PointOfSaleId)
			if err != nil {
				fmt.Printf("[RegularAuction] Error getting item source strategy: %v\n", err)
			} else {
				item, err = itemSourceStrategy.GetItemByID(ctx, itemSpec.ItemId)
				if err != nil {
					fmt.Printf("[RegularAuction] Error getting item from %s source: %v\n", itemSourceStrategy.GetSourceType(), err)
				}
			}

			if item != nil {
				orderCreationStrategy, err := s.orderCreationFactory.GetStrategy(ctx, string(itemSpec.GetSource()), order.PointOfSaleId)
				if err != nil {
					fmt.Printf("[RegularAuction] Cannot create external order: %v\n", err)
				} else {
					fmt.Printf("[RegularAuction] Creating shopping cart item for order %s\n", order.OrderId)
					err = orderCreationStrategy.CreateExternalOrder(ctx, billing, order, item, itemSpec)
					if err != nil {
						fmt.Printf("[RegularAuction] Error creating shopping cart item: %v\n", err)
					} else {
						fmt.Printf("[RegularAuction] Shopping cart item created successfully\n")
						source := string(itemSpec.GetSource())
						ordersBySource[source] = append(ordersBySource[source], order)
					}
				}
			}
		}

		result.ProcessedOrders++
	}

	if state == "Approved" && len(ordersBySource) > 0 {
		fmt.Printf("[RegularAuction] Finalizing orders for %d sources\n", len(ordersBySource))

		for source, sourceOrders := range ordersBySource {
			if len(sourceOrders) == 0 {
				continue
			}

			orderCreationStrategy, err := s.orderCreationFactory.GetStrategy(ctx, source, sourceOrders[0].PointOfSaleId)
			if err != nil {
				fmt.Printf("[RegularAuction] Cannot finalize orders for source %s: %v\n", source, err)
				continue
			}

			fmt.Printf("[RegularAuction] Finalizing %d orders for source %s\n", len(sourceOrders), source)
			invoiceURL, err := orderCreationStrategy.FinalizeOrder(ctx, billing, sourceOrders)
			if err != nil {
				fmt.Printf("[RegularAuction] Error finalizing orders: %v\n", err)
			} else {
				fmt.Printf("[RegularAuction] Orders finalized successfully with invoice URL: %s\n", invoiceURL)
				for _, order := range sourceOrders {
					order.SiigoInvoicePublicURL = invoiceURL
				}
			}
		}
	}

	fmt.Printf("[RegularAuction] Processed %d orders (created external orders without modifying local state)\n", result.ProcessedOrders)

	return result, nil
}

func (s *RegularAuctionStrategy) GetOfferType() string {
	return "regular_auction"
}
