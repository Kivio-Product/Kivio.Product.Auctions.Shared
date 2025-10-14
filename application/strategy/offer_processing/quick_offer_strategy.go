package offer_processing

import (
	"context"
	"fmt"

	offerService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/offer"
	strategyApp "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/strategy"
	billingDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/billing"
	itemDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
	domainStrategy "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/strategy"
	itemSpecInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/item_specification"
	orderInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/order"
)

type QuickOfferStrategy struct {
	itemSpecRepo         itemSpecInfrastructure.ItemSpecificationRepository
	orderRepo            orderInfrastructure.OrderRepository
	itemSourceFactory    *strategyApp.ItemSourceFactory
	orderCreationFactory *strategyApp.OrderCreationStrategyFactory
	offerService         offerService.IOfferService
}

func NewQuickOfferStrategy(
	itemSpecRepo itemSpecInfrastructure.ItemSpecificationRepository,
	orderRepo orderInfrastructure.OrderRepository,
	itemSourceFactory *strategyApp.ItemSourceFactory,
	orderCreationFactory *strategyApp.OrderCreationStrategyFactory,
	offerService offerService.IOfferService,
) *QuickOfferStrategy {
	return &QuickOfferStrategy{
		itemSpecRepo:         itemSpecRepo,
		orderRepo:            orderRepo,
		itemSourceFactory:    itemSourceFactory,
		orderCreationFactory: orderCreationFactory,
		offerService:         offerService,
	}
}

func (s *QuickOfferStrategy) ProcessApprovedOrders(
	ctx context.Context,
	orders []*orderDomain.Order,
	billing *billingDomain.Billing,
	state string,
) (*domainStrategy.OfferProcessingResult, error) {

	result := &domainStrategy.OfferProcessingResult{
		ItemNames:   []string{},
		TotalAmount: 0,
	}

	var itemSpecsAvailability []int64
	var offerID string

	for _, order := range orders {
		itemSpec, err := s.itemSpecRepo.GetById(ctx, order.ItemSpecificationId)
		if err != nil {
			fmt.Printf("no se encontro el itemSpec con Id: %s\n", order.ItemSpecificationId)
			continue
		}

		result.ItemNames = append(result.ItemNames, order.ExtraData)
		result.TotalAmount += int64(order.OfferedAmount)

		var item *itemDomain.Item
		itemSourceStrategy, err := s.itemSourceFactory.GetStrategyByItemSpec(ctx, string(itemSpec.GetSource()), order.PointOfSaleId)
		if err != nil {
			fmt.Printf("error getting item source strategy: %v\n", err)
		} else {
			item, err = itemSourceStrategy.GetItemByID(ctx, itemSpec.ItemId)
			if err != nil {
				fmt.Printf("error getting item from %s source: %v\n", itemSourceStrategy.GetSourceType(), err)
			}
		}

		if result.CustomerEmail == "" {
			result.CustomerEmail = order.CustomerId
		}

		if offerID == "" {
			offerID = order.OfferId
		}

		switch state {
		case "Approved":
			order.State = "Approved"
			itemSpec.Availability--

			if itemSpec.GetSource() != "" && item != nil {
				orderCreationStrategy, err := s.orderCreationFactory.GetStrategy(ctx, string(itemSpec.GetSource()), order.PointOfSaleId)
				if err != nil {
					fmt.Printf("[QuickOffer] Cannot create external order: %v\n", err)
				} else {
					err = orderCreationStrategy.CreateExternalOrder(ctx, billing, orders, item, itemSpec)
					if err != nil {
						fmt.Printf("[QuickOffer] Error creating %s order: %v\n", orderCreationStrategy.GetOrderType(), err)
					} else {
						fmt.Printf("[QuickOffer] Successfully created %s order\n", orderCreationStrategy.GetOrderType())
					}
				}
			}

		case "Rejected", "Error":
			order.State = "Rejected"
		default:
			continue
		}

		if itemSpec != nil {
			itemSpecsAvailability = append(itemSpecsAvailability, itemSpec.Availability)
		}

		err = s.orderRepo.UpdateOrder(ctx, order)
		if err != nil {
			return nil, fmt.Errorf("no se pudo actualizar la orden %s: %v", order.OrderId, err)
		}

		err = s.itemSpecRepo.UpdateItemSpec(ctx, itemSpec)
		if err != nil {
			return nil, fmt.Errorf("no se pudo actualizar el item specification %s: %v", order.ItemSpecificationId, err)
		}

		result.ProcessedOrders++
	}

	allZero := true
	for _, availability := range itemSpecsAvailability {
		if availability != 0 {
			allZero = false
			break
		}
	}

	if allZero && offerID != "" {
		err := s.offerService.UpdateOfferState(ctx, offerID, "Closed")
		if err != nil {
			return nil, fmt.Errorf("no se pudo actualizar la oferta %s: %v", offerID, err)
		}
		result.ShouldCloseOffer = true
		result.OfferID = offerID
	}

	return result, nil
}

func (s *QuickOfferStrategy) GetOfferType() string {
	return "quick_offer"
}
