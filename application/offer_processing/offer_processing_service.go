package services

import (
	"context"
	"fmt"
	"sort"

	ecommerceService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/ecommerce"
	emailService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/email"
	itemSpecDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item_specification"
	offerDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/offer"
	processingDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/offer_processing"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
	itemSpecRepository "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/item_specification"
	offerRepository "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/offer"
	orderRepository "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/order"
	posRepository "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/point_of_sale"
)

type IOfferProcessingService interface {
	ProcessOffer(ctx context.Context, offerId string) (*processingDomain.ProcessOfferResponse, error)
}

type OfferProcessingService struct {
	offerRepo        offerRepository.IOfferRepository
	orderRepo        orderRepository.OrderRepository
	itemSpecRepo     itemSpecRepository.ItemSpecificationRepository
	posRepo          posRepository.IPosRepository
	ecommerceService ecommerceService.EcommerceService
	ecommerceCredSvc ecommerceService.EcommerceCredentialsService
	emailSender      emailService.EmailServiceInterface
}

func NewOfferProcessingService(
	offerRepo offerRepository.IOfferRepository,
	orderRepo orderRepository.OrderRepository,
	itemSpecRepo itemSpecRepository.ItemSpecificationRepository,
	posRepo posRepository.IPosRepository,
	ecommerceService ecommerceService.EcommerceService,
	ecommerceCredSvc ecommerceService.EcommerceCredentialsService,
	emailSender emailService.EmailServiceInterface,
) IOfferProcessingService {
	return &OfferProcessingService{
		offerRepo:        offerRepo,
		orderRepo:        orderRepo,
		itemSpecRepo:     itemSpecRepo,
		posRepo:          posRepo,
		ecommerceService: ecommerceService,
		ecommerceCredSvc: ecommerceCredSvc,
		emailSender:      emailSender,
	}
}

func (s *OfferProcessingService) ProcessOffer(ctx context.Context, offerId string) (*processingDomain.ProcessOfferResponse, error) {
	offer, err := s.offerRepo.GetOfferById(ctx, offerId)
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
	domainOrders, err := s.orderRepo.GetOrdersByOfferId(ctx, offerId)
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
	itemSpec, err := s.itemSpecRepo.GetById(ctx, itemSpecId)
	if err != nil {
		return nil, nil, fmt.Errorf("error fetching item specification %s: %v", itemSpecId, err)
	}

	availability := 0

	if itemSpec.IsExternal {
		creds, err := s.ecommerceCredSvc.GetCredentials(ctx, posId)
		if err != nil {
			return nil, nil, fmt.Errorf("error getting ecommerce credentials: %v", err)
		}

		item, err := s.ecommerceService.GetItemByID(ctx, itemSpec.ItemId, creds.ApiURL, creds.ApiKey)
		if err != nil || item == nil {
			fmt.Printf("Error fetching external item %s or item not found\n", itemSpec.ItemId)
			availability = 0
		} else {
			availability = 0
		}
	} else {
		availability = int(itemSpec.Availability)
	}

	sort.Slice(orders, func(i, j int) bool {
		return orders[i].OfferedAmount > orders[j].OfferedAmount
	})

	var winners, losers []*orderDomain.Order
	if availability > len(orders) {
		winners = orders
	} else {
		winners = orders[:availability]
		losers = orders[availability:]
	}

	for _, winner := range winners {
		err := s.updateOrderState(ctx, winner, "Approved", true)
		if err != nil {
			fmt.Printf("Error updating winner order %s: %v\n", winner.OrderId, err)
		}
	}

	for _, loser := range losers {
		err := s.updateOrderState(ctx, loser, "Rejected", false)
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
		err := s.updateItemSpecAvailability(ctx, itemSpec, newAvailability)
		if err != nil {
			fmt.Printf("Error updating item spec availability %s: %v\n", itemSpecId, err)
		}
	}

	return winners, losers, nil
}

func (s *OfferProcessingService) updateOrderState(ctx context.Context, order *orderDomain.Order, state string, isWinner bool) error {
	order.State = state
	order.IsWinner = isWinner
	return s.orderRepo.SaveOrder(ctx, order)
}

func (s *OfferProcessingService) updateExternalItemStock(ctx context.Context, posId, itemId string, newStock int) error {
	creds, err := s.ecommerceCredSvc.GetCredentials(ctx, posId)
	if err != nil {
		return err
	}

	return s.ecommerceService.UpdateItemStock(ctx, creds.ApiURL, creds.ApiKey, itemId, newStock)
}

func (s *OfferProcessingService) updateItemSpecAvailability(ctx context.Context, itemSpec *itemSpecDomain.ItemSpecification, newAvailability int) error {
	itemSpec.Availability = int64(newAvailability)
	return s.itemSpecRepo.UpdateItemSpec(ctx, itemSpec)
}

func (s *OfferProcessingService) sendEmailsGroupedByCustomer(ctx context.Context, orders []*orderDomain.Order, status, posId string) error {
	groupedByCustomer := make(map[string][]*orderDomain.Order)
	for _, order := range orders {
		groupedByCustomer[order.CustomerId] = append(groupedByCustomer[order.CustomerId], order)
	}

	pos, err := s.posRepo.GetPosById(ctx, posId)
	if err != nil {
		fmt.Printf("Error getting POS name for ID %s: %v\n", posId, err)
		return err
	}

	for customerId, customerOrders := range groupedByCustomer {
		var itemNames []string
		var offeredAmount int64

		for _, order := range customerOrders {
			itemNames = append(itemNames, order.ExtraData)
			if offeredAmount == 0 {
				offeredAmount = order.OfferedAmount
			}
		}

		notification := processingDomain.EmailNotification{
			CustomerId:        customerId,
			OfferedAmount:     offeredAmount,
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
	err := offer.UpdateState("Closed")
	if err != nil {
		return err
	}
	return s.offerRepo.SaveOffer(ctx, offer)
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
