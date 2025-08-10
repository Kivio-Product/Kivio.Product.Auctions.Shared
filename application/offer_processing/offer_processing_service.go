package services

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	ecommerceService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/ecommerce"
	emailService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/email"
	itemSpecService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/item_specification"
	offerService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/offer"
	orderService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/order"
	paymentService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/payment"
	pointOfSaleService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/point_of_sale"
	offerDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/offer"
	processingDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/offer_processing"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
)

type IOfferProcessingService interface {
	ProcessOffer(ctx context.Context, offerId string) (*processingDomain.ProcessOfferResponse, error)
}

type OfferProcessingService struct {
	offerService     offerService.IOfferService
	orderService     orderService.OrderService
	itemSpecService  itemSpecService.ItemSpecificationService
	posService       pointOfSaleService.IPosService
	ecommerceService ecommerceService.EcommerceService
	ecommerceCredSvc ecommerceService.EcommerceCredentialsService
	emailSender      emailService.EmailServiceInterface
	paymentService   paymentService.PaymentService
}

func NewOfferProcessingService(
	offerService offerService.IOfferService,
	orderService orderService.OrderService,
	itemSpecService itemSpecService.ItemSpecificationService,
	posService pointOfSaleService.IPosService,
	ecommerceService ecommerceService.EcommerceService,
	ecommerceCredSvc ecommerceService.EcommerceCredentialsService,
	emailSender emailService.EmailServiceInterface,
	paymentService paymentService.PaymentService,
) IOfferProcessingService {
	return &OfferProcessingService{
		offerService:     offerService,
		orderService:     orderService,
		itemSpecService:  itemSpecService,
		posService:       posService,
		ecommerceService: ecommerceService,
		ecommerceCredSvc: ecommerceCredSvc,
		emailSender:      emailSender,
		paymentService:   paymentService,
	}
}

func (s *OfferProcessingService) ProcessOffer(ctx context.Context, offerId string) (*processingDomain.ProcessOfferResponse, error) {
	offer, err := s.offerService.GetOfferById(ctx, offerId)
	if err != nil {
		return &processingDomain.ProcessOfferResponse{
			Status:  "error",
			Message: fmt.Sprintf("Error fetching offer %s: %v", offerId, err),
			OfferId: offerId,
		}, err
	}

	if offer.State != "Offered" || offer.Type != "Regular auction" {
		return &processingDomain.ProcessOfferResponse{
			Status:  "skipped",
			Message: "Offer not in valid state or type for processing",
			OfferId: offerId,
		}, nil
	}

	orders, err := s.getOrdersByOffer(ctx, offerId)
	if err != nil {
		return &processingDomain.ProcessOfferResponse{
			Status:  "error",
			Message: fmt.Sprintf("Error fetching orders for offer %s: %v", offerId, err),
			OfferId: offerId,
		}, err
	}

	groupedOrders := s.groupOrdersByItemSpec(orders)

	var allWinners []*orderDomain.Order
	var allLosers []*orderDomain.Order

	for itemSpecId, ordersGroup := range groupedOrders {
		pendingOrders := s.filterPendingOrders(ordersGroup)
		if len(pendingOrders) == 0 {
			continue
		}

		winners, losers, err := s.processItemSpecOrders(ctx, itemSpecId, pendingOrders, offer.PosId)
		if err != nil {
			return &processingDomain.ProcessOfferResponse{
				Status:  "error",
				Message: fmt.Sprintf("Error processing item spec %s: %v", itemSpecId, err),
				OfferId: offerId,
			}, err
		}

		allWinners = append(allWinners, winners...)
		allLosers = append(allLosers, losers...)
	}

	successfulPaymentCustomers := s.processPaymentsByCustomer(ctx, allWinners)

	winnersWithSuccessfulPayment := s.filterWinnersBySuccessfulPayment(allWinners, successfulPaymentCustomers)
	err = s.sendEmailsGroupedByCustomer(ctx, winnersWithSuccessfulPayment, "Approved", offer.PosId)
	if err != nil {
		fmt.Printf("Error sending emails to winners for offer %s: %v\n", offerId, err)
	}

	err = s.sendEmailsGroupedByCustomer(ctx, allLosers, "Rejected", offer.PosId)
	if err != nil {
		fmt.Printf("Error sending emails for offer %s: %v\n", offerId, err)
	}

	err = s.closeOffer(ctx, offer)
	if err != nil {
		return &processingDomain.ProcessOfferResponse{
			Status:  "error",
			Message: fmt.Sprintf("Error closing offer %s: %v", offerId, err),
			OfferId: offerId,
		}, err
	}

	return &processingDomain.ProcessOfferResponse{
		Status:  "success",
		Message: fmt.Sprintf("Offer %s processed successfully. Winners: %d, Losers: %d", offerId, len(allWinners), len(allLosers)),
		OfferId: offerId,
	}, nil
}

func (s *OfferProcessingService) getOrdersByOffer(ctx context.Context, offerId string) ([]*orderDomain.Order, error) {
	domainOrders, err := s.orderService.GetOrderByOfferId(ctx, offerId)
	if err != nil {
		return nil, err
	}

	orders := make([]*orderDomain.Order, len(domainOrders))
	for i := range domainOrders {
		orders[i] = &domainOrders[i]
	}

	return orders, nil
}

func (s *OfferProcessingService) groupOrdersByItemSpec(orders []*orderDomain.Order) map[string][]*orderDomain.Order {
	grouped := make(map[string][]*orderDomain.Order)
	for _, order := range orders {
		grouped[order.ItemSpecificationId] = append(grouped[order.ItemSpecificationId], order)
	}
	return grouped
}

func (s *OfferProcessingService) filterPendingOrders(orders []*orderDomain.Order) []*orderDomain.Order {
	var pending []*orderDomain.Order
	for _, order := range orders {
		if order.State == "Pending" {
			pending = append(pending, order)
		}
	}
	return pending
}

func (s *OfferProcessingService) processItemSpecOrders(ctx context.Context, itemSpecId string, orders []*orderDomain.Order, posId string) ([]*orderDomain.Order, []*orderDomain.Order, error) {
	itemSpec, err := s.itemSpecService.GetById(ctx, itemSpecId)
	if err != nil {
		return nil, nil, fmt.Errorf("error fetching item specification %s: %v", itemSpecId, err)
	}

	availability := 0

	if itemSpec.IsExternal {
		creds, err := s.ecommerceCredSvc.GetCredentials(ctx, posId)
		if err != nil {
			return nil, nil, fmt.Errorf("error getting ecommerce credentials: %v", err)
		}

		itemId := strings.TrimPrefix(itemSpec.ItemId, "kivio-ecommerce∼")
		itemRaw, err := s.ecommerceService.GetItemByIDRaw(ctx, itemId, creds.ApiURL, creds.ApiKey)
		if err != nil || itemRaw == nil {
			fmt.Printf("Error fetching external item %s or item not found\n", itemSpec.ItemId)
			availability = 0
		} else {
			type externalProductResponse struct {
				Products []struct {
					StockQuantity int64 `json:"stock_quantity"`
				} `json:"products"`
			}
			var extResp externalProductResponse
			if err := json.Unmarshal(itemRaw, &extResp); err == nil && len(extResp.Products) > 0 {
				availability = int(extResp.Products[0].StockQuantity)
			} else {
				fmt.Printf("Error parsing external item response or no products found for %s\n", itemSpec.ItemId)
				availability = 0
			}
		}
	} else {
		availability = int(itemSpec.Availability)
	}

	sort.Slice(orders, func(i, j int) bool {
		return orders[i].OfferedAmount > orders[j].OfferedAmount
	})

	var winners, losers []*orderDomain.Order
	winnerCount := 0
	for _, order := range orders {
		if winnerCount < availability {
			winners = append(winners, order)
			winnerCount++
		} else {
			losers = append(losers, order)
		}
	}

	for _, winner := range winners {
		input := orderDomain.OrderInput{
			OrderId:             winner.OrderId,
			CustomerId:          winner.CustomerId,
			ExternalId:          winner.ExternalId,
			ItemSpecificationId: winner.ItemSpecificationId,
			State:               "Approved",
			OfferedAmount:       winner.OfferedAmount,
			IsWinner:            true,
		}
		err := s.orderService.UpdateOrder(ctx, input)
		if err != nil {
			fmt.Printf("Error updating winner order %s: %v\n", winner.OrderId, err)
		}
	}

	for _, loser := range losers {
		input := orderDomain.OrderInput{
			OrderId:             loser.OrderId,
			CustomerId:          loser.CustomerId,
			ExternalId:          loser.ExternalId,
			ItemSpecificationId: loser.ItemSpecificationId,
			State:               "Rejected",
			OfferedAmount:       loser.OfferedAmount,
			IsWinner:            false,
		}
		err := s.orderService.UpdateOrder(ctx, input)
		if err != nil {
			fmt.Printf("Error updating loser order %s: %v\n", loser.OrderId, err)
		}
	}

	if itemSpec.IsExternal {
		if len(winners) > 0 {
			newStock := availability - len(winners)
			err := s.updateExternalItemStock(ctx, posId, itemSpec.ItemId, newStock)
			if err != nil {
				fmt.Printf("Error updating external stock for item %s: %v\n", itemSpec.ItemId, err)
			}
		}
	} else {
		newAvailability := availability - len(winners)
		err := s.itemSpecService.Update(ctx, itemSpec.Id, itemSpec.Currency, itemSpec.OfferId, itemSpec.ItemId, itemSpec.PointOfSaleId, itemSpec.Amount, int64(newAvailability), itemSpec.ExpireAt)
		if err != nil {
			fmt.Printf("Error updating item spec availability %s: %v\n", itemSpecId, err)
		}
	}

	return winners, losers, nil
}

func (s *OfferProcessingService) updateExternalItemStock(ctx context.Context, posId, itemId string, newStock int) error {
	creds, err := s.ecommerceCredSvc.GetCredentials(ctx, posId)
	if err != nil {
		return err
	}

	itemId = strings.TrimPrefix(itemId, "kivio-ecommerce∼")

	return s.ecommerceService.UpdateItemStock(ctx, creds.ApiURL, creds.ApiKey, itemId, newStock)
}

func (s *OfferProcessingService) sendEmailsGroupedByCustomer(ctx context.Context, orders []*orderDomain.Order, status, posId string) error {
	groupedByCustomer := make(map[string][]*orderDomain.Order)
	for _, order := range orders {
		groupedByCustomer[order.CustomerId] = append(groupedByCustomer[order.CustomerId], order)
	}

	pos, err := s.posService.GetPosById(ctx, posId)
	if err != nil {
		fmt.Printf("Error getting POS name for ID %s: %v\n", posId, err)
		return err
	}

	for customerId, customerOrders := range groupedByCustomer {
		itemCounts := make(map[string]int)
		var totalOfferedAmount int64

		for _, order := range customerOrders {
			itemCounts[order.ExtraData]++
			totalOfferedAmount += order.OfferedAmount
		}

		var itemNames []string
		for itemName, count := range itemCounts {
			if count > 1 {
				itemNames = append(itemNames, fmt.Sprintf("%s x%d unds", itemName, count))
			} else {
				itemNames = append(itemNames, itemName)
			}
		}

		notification := processingDomain.EmailNotification{
			CustomerId:        customerId,
			OfferedAmount:     totalOfferedAmount,
			Status:            status,
			ConcatenatedNames: joinStrings(itemNames, ", "),
			PointOfSaleId:     pos.Name,
		}

		err := s.sendEmailNotification(ctx, notification)
		if err != nil {
			fmt.Printf("Error sending email to customer %s: %v\n", customerId, err)
		}
	}

	return nil
}

func (s *OfferProcessingService) sendEmailNotification(ctx context.Context, notification processingDomain.EmailNotification) error {
	return s.emailSender.NotifyOrderStatus(ctx,
		notification.CustomerId,
		notification.Status,
		notification.ConcatenatedNames,
		notification.OfferedAmount,
		notification.PointOfSaleId,
	)
}

func (s *OfferProcessingService) closeOffer(ctx context.Context, offer *offerDomain.Offer) error {
	return s.offerService.UpdateOfferState(ctx, offer.OfferId, "Closed")
}

func (s *OfferProcessingService) processPaymentsByCustomer(ctx context.Context, allWinners []*orderDomain.Order) []string {
	winnersByCustomer := make(map[string][]*orderDomain.Order)
	var successfulCustomers []string

	for _, winner := range allWinners {
		winnersByCustomer[winner.CustomerId] = append(winnersByCustomer[winner.CustomerId], winner)
	}

	for customerId, orders := range winnersByCustomer {
		err := s.paymentService.ProcessPaymentForCustomer(ctx, orders)
		if err != nil {
			fmt.Printf("Error processing payment for customer %s: %v\n", customerId, err)
			continue
		}
		fmt.Printf("Successfully processed payment for customer %s with %d orders\n", customerId, len(orders))
		successfulCustomers = append(successfulCustomers, customerId)
	}

	return successfulCustomers
}

func (s *OfferProcessingService) filterWinnersBySuccessfulPayment(allWinners []*orderDomain.Order, successfulCustomers []string) []*orderDomain.Order {
	successfulCustomersMap := make(map[string]bool)
	for _, customerId := range successfulCustomers {
		successfulCustomersMap[customerId] = true
	}

	var winnersWithSuccessfulPayment []*orderDomain.Order
	for _, winner := range allWinners {
		if successfulCustomersMap[winner.CustomerId] {
			winnersWithSuccessfulPayment = append(winnersWithSuccessfulPayment, winner)
		}
	}

	return winnersWithSuccessfulPayment
}

func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	if len(strs) == 1 {
		return strs[0]
	}

	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}
