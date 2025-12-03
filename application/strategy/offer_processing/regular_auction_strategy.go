package offer_processing

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	ecommerceService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/ecommerce"
	strategyApp "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/strategy"
	billingDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/billing"
	itemDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
	itemSpecDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item_specification"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
	domainStrategy "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/strategy"
	itemSpecInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/item_specification"
	orderInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/order"
)

type RegularAuctionStrategy struct {
	itemSpecRepo         itemSpecInfrastructure.ItemSpecificationRepository
	orderRepo            orderInfrastructure.OrderRepository
	itemSourceFactory    *strategyApp.ItemSourceFactory
	orderCreationFactory *strategyApp.OrderCreationStrategyFactory
	ecommerceService     ecommerceService.EcommerceService
	ecommerceCredSvc     ecommerceService.EcommerceCredentialsService
}

func NewRegularAuctionStrategy(
	itemSpecRepo itemSpecInfrastructure.ItemSpecificationRepository,
	orderRepo orderInfrastructure.OrderRepository,
	itemSourceFactory *strategyApp.ItemSourceFactory,
	orderCreationFactory *strategyApp.OrderCreationStrategyFactory,
	ecommerceService ecommerceService.EcommerceService,
	ecommerceCredSvc ecommerceService.EcommerceCredentialsService,
) *RegularAuctionStrategy {
	return &RegularAuctionStrategy{
		itemSpecRepo:         itemSpecRepo,
		orderRepo:            orderRepo,
		itemSourceFactory:    itemSourceFactory,
		orderCreationFactory: orderCreationFactory,
		ecommerceService:     ecommerceService,
		ecommerceCredSvc:     ecommerceCredSvc,
	}
}

func (s *RegularAuctionStrategy) ProcessApprovedOrders(
	ctx context.Context,
	orders []*orderDomain.Order,
	billing *billingDomain.Billing,
	state string,
) (*domainStrategy.OfferProcessingResult, error) {

	fmt.Printf("[RegularAuction] Processing payment confirmation for %d orders\n", len(orders))
	fmt.Printf("[RegularAuction] Payment state: %s\n", state)

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

		if state == "Approved" && order.State == "Approved" {
			fmt.Printf("[RegularAuction] Reducing availability for order %s (ItemSpec: %s, Quantity: %d)\n",
				order.OrderId, order.ItemSpecificationId, order.TotalQuantity)

			err := s.reduceAvailability(ctx, itemSpec, order)
			if err != nil {
				fmt.Printf("[RegularAuction] ERROR reducing availability: %v\n", err)
			}
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

					err := s.orderRepo.UpdateOrder(ctx, order)
					if err != nil {
						fmt.Printf("[RegularAuction] ERROR: Failed to save order %s with invoice URL: %v\n", order.OrderId, err)
					} else {
						fmt.Printf("[RegularAuction] Order %s saved successfully with invoice URL\n", order.OrderId)
					}
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

func (s *RegularAuctionStrategy) reduceAvailability(
	ctx context.Context,
	itemSpec *itemSpecDomain.ItemSpecification,
	order *orderDomain.Order,
) error {
	source := string(itemSpec.GetSource())

	if source != "" && source != "local" {
		fmt.Printf("[RegularAuction] Reducing EXTERNAL stock for source: %s\n", source)

		itemSourceStrategy, err := s.itemSourceFactory.GetStrategyByItemSpec(ctx, source, order.PointOfSaleId)
		if err != nil {
			return fmt.Errorf("error getting item source strategy for %s: %w", source, err)
		}

		currentStock, err := s.getCurrentExternalStock(ctx, itemSourceStrategy, itemSpec, order.PointOfSaleId)
		if err != nil {
			fmt.Printf("[RegularAuction] WARNING: Could not fetch current external stock, using itemSpec availability: %v\n", err)
			currentStock = int(itemSpec.Availability)
		}

		newStock := currentStock - order.TotalQuantity

		fmt.Printf("[RegularAuction] External stock update: %d - %d = %d\n", currentStock, order.TotalQuantity, newStock)

		if newStock < 0 {
			fmt.Printf("[RegularAuction] WARNING: newStock is NEGATIVE (%d)\n", newStock)
		}

		err = itemSourceStrategy.UpdateItemStock(ctx, itemSpec.ItemId, newStock)
		if err != nil {
			return fmt.Errorf("error updating external stock: %w", err)
		}

		itemSpec.Availability = int64(newStock)
		err = s.itemSpecRepo.UpdateItemSpec(ctx, itemSpec)
		if err != nil {
			fmt.Printf("[RegularAuction] WARNING: External stock updated but failed to update itemSpec: %v\n", err)
		}

		fmt.Printf("[RegularAuction] External stock updated successfully to %d\n", newStock)
	} else {
		fmt.Printf("[RegularAuction] Reducing LOCAL availability\n")

		currentAvailability := int(itemSpec.Availability)
		newAvailability := currentAvailability - order.TotalQuantity

		fmt.Printf("[RegularAuction] Local availability update: %d - %d = %d\n", currentAvailability, order.TotalQuantity, newAvailability)

		if newAvailability < 0 {
			fmt.Printf("[RegularAuction] WARNING: newAvailability is NEGATIVE (%d)\n", newAvailability)
		}

		itemSpec.Availability = int64(newAvailability)

		err := s.itemSpecRepo.UpdateItemSpec(ctx, itemSpec)
		if err != nil {
			return fmt.Errorf("error updating itemSpec availability: %w", err)
		}

		fmt.Printf("[RegularAuction] Local availability updated successfully to %d\n", newAvailability)
	}

	return nil
}

func (s *RegularAuctionStrategy) getCurrentExternalStock(
	ctx context.Context,
	itemSourceStrategy domainStrategy.ItemSourceStrategy,
	itemSpec *itemSpecDomain.ItemSpecification,
	posID string,
) (int, error) {
	creds, err := s.ecommerceCredSvc.GetCredentials(ctx, posID)
	if err != nil {
		return 0, fmt.Errorf("error getting ecommerce credentials: %w", err)
	}

	itemID := strings.TrimPrefix(itemSpec.ItemId, "kivio-ecommerce∼")

	itemRaw, err := s.ecommerceService.GetItemByIDRaw(ctx, itemID, creds.ApiURL, creds.ApiKey)
	if err != nil || itemRaw == nil {
		return 0, fmt.Errorf("error fetching external item %s or item not found: %w", itemSpec.ItemId, err)
	}

	type externalProductResponse struct {
		Products []struct {
			StockQuantity int64 `json:"stock_quantity"`
		} `json:"products"`
	}
	var extResp externalProductResponse
	if err := json.Unmarshal(itemRaw, &extResp); err != nil {
		return 0, fmt.Errorf("error parsing external item response: %w", err)
	}

	if len(extResp.Products) == 0 {
		return 0, fmt.Errorf("no products found in external response for %s", itemSpec.ItemId)
	}

	currentStock := int(extResp.Products[0].StockQuantity)
	fmt.Printf("[RegularAuction] Fetched current stock from ecommerce: %d\n", currentStock)

	return currentStock, nil
}
