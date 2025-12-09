package offer_processing

import (
	"context"
	"fmt"
	"net/url"
	"os"

	offerService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/offer"
	strategyApp "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/strategy"
	billingDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/billing"
	itemDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
	domainStrategy "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/strategy"
	billingInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/billing"
	itemSpecInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/item_specification"
	orderInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/order"
)

type QuickOfferStrategy struct {
	itemSpecRepo         itemSpecInfrastructure.ItemSpecificationRepository
	orderRepo            orderInfrastructure.OrderRepository
	billingRepo          billingInfrastructure.BillingRepository
	itemSourceFactory    *strategyApp.ItemSourceFactory
	orderCreationFactory *strategyApp.OrderCreationStrategyFactory
	offerService         offerService.IOfferService
}

func NewQuickOfferStrategy(
	itemSpecRepo itemSpecInfrastructure.ItemSpecificationRepository,
	orderRepo orderInfrastructure.OrderRepository,
	billingRepo billingInfrastructure.BillingRepository,
	itemSourceFactory *strategyApp.ItemSourceFactory,
	orderCreationFactory *strategyApp.OrderCreationStrategyFactory,
	offerService offerService.IOfferService,
) *QuickOfferStrategy {
	return &QuickOfferStrategy{
		itemSpecRepo:         itemSpecRepo,
		orderRepo:            orderRepo,
		billingRepo:          billingRepo,
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

	ordersBySource := make(map[string][]*orderDomain.Order)

	fmt.Printf("[QuickOffer] Processing %d orders\n", len(orders))

	for _, order := range orders {
		itemSpec, err := s.itemSpecRepo.GetById(ctx, order.ItemSpecificationId)
		if err != nil {
			fmt.Printf("[QuickOffer] No se encontro el itemSpec con Id: %s\n", order.ItemSpecificationId)
			continue
		}

		result.ItemNames = append(result.ItemNames, order.ExtraData)
		result.TotalAmount += int64(order.OfferedAmount)

		if result.CustomerEmail == "" {
			result.CustomerEmail = order.CustomerId
		}

		if offerID == "" {
			offerID = order.OfferId
		}

		var item *itemDomain.Item
		if itemSpec.GetSource() != "" {
			itemSourceStrategy, err := s.itemSourceFactory.GetStrategyByItemSpec(ctx, string(itemSpec.GetSource()), order.PointOfSaleId)
			if err != nil {
				fmt.Printf("[QuickOffer] Error getting item source strategy: %v\n", err)
			} else {
				item, err = itemSourceStrategy.GetItemByID(ctx, itemSpec.ItemId)
				if err != nil {
					fmt.Printf("[QuickOffer] Error getting item from %s source: %v\n", itemSourceStrategy.GetSourceType(), err)
				}
			}
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
					fmt.Printf("[QuickOffer] Creating shopping cart item for order %s\n", order.OrderId)
					err = orderCreationStrategy.CreateExternalOrder(ctx, billing, order, item, itemSpec)
					if err != nil {
						fmt.Printf("[QuickOffer] Error creating shopping cart item: %v\n", err)
					} else {
						fmt.Printf("[QuickOffer] Shopping cart item created successfully\n")
						source := string(itemSpec.GetSource())
						ordersBySource[source] = append(ordersBySource[source], order)
					}
				}
			}

		case "Rejected", "Error":
			order.State = "Rejected"
		default:
			continue
		}

		err = s.orderRepo.UpdateOrder(ctx, order)
		if err != nil {
			return nil, fmt.Errorf("no se pudo actualizar la orden %s: %v", order.OrderId, err)
		}

		if itemSpec != nil {
			itemSpecsAvailability = append(itemSpecsAvailability, itemSpec.Availability)

			err = s.itemSpecRepo.UpdateItemSpec(ctx, itemSpec)
			if err != nil {
				return nil, fmt.Errorf("no se pudo actualizar el item specification %s: %v", order.ItemSpecificationId, err)
			}
		}

		result.ProcessedOrders++
	}

	if state == "Approved" && len(ordersBySource) > 0 {
		fmt.Printf("[QuickOffer] Finalizing orders for %d sources\n", len(ordersBySource))

		for source, sourceOrders := range ordersBySource {
			if len(sourceOrders) == 0 {
				continue
			}

			orderCreationStrategy, err := s.orderCreationFactory.GetStrategy(ctx, source, sourceOrders[0].PointOfSaleId)
			if err != nil {
				fmt.Printf("[QuickOffer] Cannot finalize orders for source %s: %v\n", source, err)
				continue
			}

			fmt.Printf("[QuickOffer] Finalizing %d orders for source %s\n", len(sourceOrders), source)
			invoiceURL, err := orderCreationStrategy.FinalizeOrder(ctx, billing, sourceOrders)
			if err != nil {
				fmt.Printf("[QuickOffer] Error finalizing orders: %v\n", err)
			} else {
				fmt.Printf("[QuickOffer] Orders finalized successfully with invoice URL: %s\n", invoiceURL)

				fullInvoiceURL := s.constructSiigoInvoiceURL(invoiceURL, billing.Id)
				fmt.Printf("[QuickOffer] Constructed full Siigo invoice URL: %s\n", fullInvoiceURL)

				for _, order := range sourceOrders {
					order.SiigoInvoicePublicURL = invoiceURL

					err := s.orderRepo.UpdateOrder(ctx, order)
					if err != nil {
						fmt.Printf("[QuickOffer] ERROR: Failed to save order %s with invoice URL: %v\n", order.OrderId, err)
					} else {
						fmt.Printf("[QuickOffer] Order %s saved successfully with invoice URL\n", order.OrderId)
					}
				}

				billing.SiigoInvoiceURL = fullInvoiceURL
				err = s.billingRepo.UpdateBilling(ctx, billing)
				if err != nil {
					fmt.Printf("[QuickOffer] ERROR: Failed to save billing %s with Siigo invoice URL: %v\n", billing.Id, err)
				} else {
					fmt.Printf("[QuickOffer] Billing %s saved successfully with Siigo invoice URL\n", billing.Id)
				}
			}
		}
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

func (s *QuickOfferStrategy) constructSiigoInvoiceURL(invoiceURL string, billingID string) string {
	if invoiceURL == "" || invoiceURL == "null" {
		fmt.Printf("[QuickOffer] Invoice URL is null or empty, returning empty string\n")
	}

	auctionsEnv := os.Getenv("AUCTIONS_ENV")
	if auctionsEnv == "" {
		fmt.Printf("[QuickOffer] WARNING: AUCTIONS_ENV not set, using invoiceURL as-is\n")
		return invoiceURL
	}

	fullURL := fmt.Sprintf("%s/auctions/invoice-wait?invoiceUrl=%s&billingId=%s",
		auctionsEnv,
		url.QueryEscape(invoiceURL),
		url.QueryEscape(billingID))

	return fullURL
}
