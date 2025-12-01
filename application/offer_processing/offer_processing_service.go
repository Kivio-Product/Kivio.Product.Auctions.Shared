package services

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	billingService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/billing"
	ecommerceService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/ecommerce"
	emailService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/email"
	invoiceService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/invoice"
	itemSpecService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/item_specification"
	offerService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/offer"
	orderService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/order"
	paymentService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/payment"
	pointOfSaleService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/point_of_sale"
	offerDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/offer"
	processingDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/offer_processing"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
	billingInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/billing"
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
	invoiceService   invoiceService.InvoiceService
	billingService   billingService.BillingService
	billingRepo      billingInfrastructure.BillingRepository
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
	invoiceService invoiceService.InvoiceService,
	billingService billingService.BillingService,
	billingRepo billingInfrastructure.BillingRepository,
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
		invoiceService:   invoiceService,
		billingService:   billingService,
		billingRepo:      billingRepo,
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

	fmt.Printf("\n========== PROCESANDO OFFER: %s ==========\n", offerId)
	fmt.Printf("Total ItemSpecs a procesar: %d\n", len(groupedOrders))

	for itemSpecId, ordersGroup := range groupedOrders {
		pendingOrders := s.filterPendingOrders(ordersGroup)
		if len(pendingOrders) == 0 {
			fmt.Printf("ItemSpec %s: No tiene órdenes pendientes, saltando...\n", itemSpecId)
			continue
		}

		fmt.Printf("\n--- Procesando ItemSpec: %s ---\n", itemSpecId)
		fmt.Printf("Órdenes pendientes para este ItemSpec: %d\n", len(pendingOrders))

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

	fmt.Printf("\n========== RESUMEN FINAL OFFER: %s ==========\n", offerId)
	fmt.Printf("TOTAL GANADORAS: %d órdenes\n", len(allWinners))
	if len(allWinners) > 0 {
		fmt.Println("Detalle de órdenes GANADORAS:")
		for i, winner := range allWinners {
			fmt.Printf("  %d. OrderId: %s | Customer: %s | ItemSpec: %s | Amount: %d | Quantity: %d\n",
				i+1, winner.OrderId, winner.CustomerId, winner.ItemSpecificationId, winner.OfferedAmount, winner.TotalQuantity)
		}
	}

	fmt.Printf("\nTOTAL PERDEDORAS: %d órdenes\n", len(allLosers))
	if len(allLosers) > 0 {
		fmt.Println("Detalle de órdenes PERDEDORAS:")
		for i, loser := range allLosers {
			fmt.Printf("  %d. OrderId: %s | Customer: %s | ItemSpec: %s | Amount: %d | Quantity: %d\n",
				i+1, loser.OrderId, loser.CustomerId, loser.ItemSpecificationId, loser.OfferedAmount, loser.TotalQuantity)
		}
	}
	fmt.Println("=============================================\n")

	successfulPaymentCustomers := s.processPaymentsByCustomer(ctx, allWinners)

	fmt.Println("SuccessfulPaymentCustomers", successfulPaymentCustomers)

	fmt.Printf("\n========== FALLBACK: PROMOTING LOSERS FOR FAILED PAYMENTS ==========\n")
	maxFallbackIterations := 3
	for iteration := 1; iteration <= maxFallbackIterations; iteration++ {
		fmt.Printf("\n[Fallback] Iteration %d/%d\n", iteration, maxFallbackIterations)

		failedWinners := s.identifyFailedPaymentWinners(allWinners, successfulPaymentCustomers)
		if len(failedWinners) == 0 {
			fmt.Printf("[Fallback] No failed payment winners in iteration %d - exiting fallback loop\n", iteration)
			break
		}

		fmt.Printf("[Fallback] Found %d winners with failed payments\n", len(failedWinners))

		failedWinnersByItemSpec := s.groupOrdersByItemSpec(failedWinners)

		var allPromotedWinners []*orderDomain.Order
		hasPromotions := false

		for itemSpecId, itemSpecFailedWinners := range failedWinnersByItemSpec {
			fmt.Printf("\n[Fallback] Processing ItemSpec %s with %d failed winners\n", itemSpecId, len(itemSpecFailedWinners))

			promotedWinners, err := s.promoteLoserWithFailedPayments(ctx, itemSpecFailedWinners, allLosers, itemSpecId)
			if err != nil {
				fmt.Printf("[Fallback] Error promoting losers for ItemSpec %s: %v\n", itemSpecId, err)
				continue
			}

			if len(promotedWinners) > 0 {
				hasPromotions = true

				err = s.updateOrderStatesAfterPromotion(ctx, promotedWinners, itemSpecFailedWinners)
				if err != nil {
					fmt.Printf("[Fallback] Error updating order states: %v\n", err)
					continue
				}

				allPromotedWinners = append(allPromotedWinners, promotedWinners...)

				var updatedAllWinners []*orderDomain.Order
				for _, w := range allWinners {
					isFailed := false
					for _, fw := range itemSpecFailedWinners {
						if w.OrderId == fw.OrderId {
							isFailed = true
							break
						}
					}
					if !isFailed {
						updatedAllWinners = append(updatedAllWinners, w)
					}
				}
				allWinners = updatedAllWinners

				allWinners = append(allWinners, promotedWinners...)

				var updatedAllLosers []*orderDomain.Order
				for _, l := range allLosers {
					isPromoted := false
					for _, pw := range promotedWinners {
						if l.OrderId == pw.OrderId {
							isPromoted = true
							break
						}
					}
					if !isPromoted {
						updatedAllLosers = append(updatedAllLosers, l)
					}
				}
				allLosers = updatedAllLosers
			}
		}

		if !hasPromotions {
			fmt.Printf("[Fallback] No promotions possible in iteration %d - exiting fallback loop\n", iteration)
			break
		}

		fmt.Printf("\n[Fallback] Processing payments for %d promoted winners\n", len(allPromotedWinners))
		newSuccessfulCustomers := s.processPaymentsByCustomer(ctx, allPromotedWinners)
		successfulPaymentCustomers = append(successfulPaymentCustomers, newSuccessfulCustomers...)

		fmt.Printf("[Fallback] Iteration %d complete: %d new successful payments\n", iteration, len(newSuccessfulCustomers))
	}
	fmt.Printf("====================================================================\n\n")

	winnersByCustomer := make(map[string][]*orderDomain.Order)
	var losersWithoutBillingApproved []*orderDomain.Order

	for _, winner := range allWinners {
		winnersByCustomer[winner.CustomerId] = append(winnersByCustomer[winner.CustomerId], winner)
	}

	for _, loser := range allLosers {
		winners, exists := winnersByCustomer[loser.CustomerId]
		if !exists || len(winners) == 0 {
			losersWithoutBillingApproved = append(losersWithoutBillingApproved, loser)
		}
	}

	err = s.sendEmailsGroupedByCustomer(ctx, losersWithoutBillingApproved, "Rejected", offer.PosId)
	if err != nil {
		fmt.Printf("Error sending emails for offer %s: %v\n", offerId, err)
	}

	s.updateBillingState(ctx, losersWithoutBillingApproved, "Rejected")

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
	fmt.Printf("\n>>> processItemSpecOrders - ItemSpecId: %s <<<\n", itemSpecId)

	itemSpec, err := s.itemSpecService.GetById(ctx, itemSpecId)
	if err != nil {
		return nil, nil, fmt.Errorf("error fetching item specification %s: %v", itemSpecId, err)
	}

	fmt.Printf("ItemSpec recuperado - ItemId: %s | IsExternal: %v | Availability inicial en DB: %d\n",
		itemSpec.ItemId, itemSpec.IsExternal, itemSpec.Availability)

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
				fmt.Printf("Availability obtenido de sistema externo: %d\n", availability)
			} else {
				fmt.Printf("Error parsing external item response or no products found for %s\n", itemSpec.ItemId)
				availability = 0
			}
		}
	} else {
		availability = int(itemSpec.Availability)
		fmt.Printf("Usando Availability local: %d\n", availability)
	}

	sort.Slice(orders, func(i, j int) bool {
		return orders[i].OfferedAmount > orders[j].OfferedAmount
	})

	fmt.Printf("\nProcesando %d órdenes pendientes (ordenadas por OfferedAmount DESC):\n", len(orders))
	for i, order := range orders {
		fmt.Printf("  %d. OrderId: %s | Customer: %s | OfferedAmount: %d | Quantity: %d\n",
			i+1, order.OrderId, order.CustomerId, order.OfferedAmount, order.TotalQuantity)
	}

	var winners, losers []*orderDomain.Order
	totalQuantityAllocated := 0
	fmt.Printf("\nDistribuyendo disponibilidad (%d unidades disponibles):\n", availability)
	for _, order := range orders {
		if totalQuantityAllocated+order.TotalQuantity <= availability {
			winners = append(winners, order)
			totalQuantityAllocated += order.TotalQuantity
			fmt.Printf("  ✓ GANADORA - OrderId: %s | Quantity: %d | Total asignado hasta ahora: %d/%d\n",
				order.OrderId, order.TotalQuantity, totalQuantityAllocated, availability)
		} else {
			losers = append(losers, order)
			fmt.Printf("  ✗ PERDEDORA - OrderId: %s | Quantity: %d | Excede disponibilidad (necesitaría: %d, solo quedan: %d)\n",
				order.OrderId, order.TotalQuantity, totalQuantityAllocated+order.TotalQuantity, availability-totalQuantityAllocated)
		}
	}

	fmt.Printf("\nResultado: %d GANADORAS, %d PERDEDORAS\n", len(winners), len(losers))

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

	fmt.Printf("\n=== WINNER/LOSER DETERMINATION COMPLETE ===\n")
	fmt.Printf("Winners: %d | Losers: %d\n", len(winners), len(losers))
	fmt.Printf("===========================================\n\n")

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

func (s *OfferProcessingService) updateBillingState(ctx context.Context, orders []*orderDomain.Order, status string) {
	groupedByBilling := make(map[string][]*orderDomain.Order)
	for _, order := range orders {
		groupedByBilling[order.BillingId] = append(groupedByBilling[order.BillingId], order)
	}

	for billingId, _ := range groupedByBilling {
		billing, err := s.billingService.GetBillingById(ctx, billingId)
		if err != nil {
			fmt.Printf("Error getting billing %s: %v\n", billingId, err)
			continue
		}
		if billing.State != "Approved" {
			billing.State = status
			err := s.billingRepo.UpdateBilling(ctx, billing)
			if err != nil {
				fmt.Printf("Error updating billing %s to status %s: %v\n", billingId, status, err)
			}
		}
	}
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
		var itemNames []string

		for _, order := range customerOrders {
			itemInfo := fmt.Sprintf("%s %d UND", order.ExtraData, order.TotalQuantity)
			itemNames = append(itemNames, itemInfo)
			itemCounts[order.ExtraData] += order.TotalQuantity
			totalOfferedAmount += order.OfferedAmount
		}

		notification := processingDomain.EmailNotification{
			CustomerId:        customerId,
			OfferedAmount:     totalOfferedAmount,
			Status:            status,
			ConcatenatedNames: joinStrings(itemNames, ", "),
			PointOfSaleId:     pos.Name,
		}
		fmt.Println("ITEMnAMES CONCATENATED", itemNames)

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
		"",
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

		go s.createInvoiceForSuccessfulPayment(ctx, orders, customerId)

		successfulCustomers = append(successfulCustomers, customerId)
	}

	return successfulCustomers
}

func (s *OfferProcessingService) filterWinnersBySuccessfulPayment(allWinners []*orderDomain.Order, successfulCustomers []string) ([]*orderDomain.Order, []*orderDomain.Order) {
	successfulCustomersMap := make(map[string]bool)
	for _, customerId := range successfulCustomers {
		successfulCustomersMap[customerId] = true
	}

	var winnersWithSuccessfulPayment []*orderDomain.Order
	var winnersWithUnsuccessfulPayment []*orderDomain.Order

	for _, winner := range allWinners {
		if successfulCustomersMap[winner.CustomerId] {
			winnersWithSuccessfulPayment = append(winnersWithSuccessfulPayment, winner)
		} else {
			winnersWithUnsuccessfulPayment = append(winnersWithUnsuccessfulPayment, winner)
		}
	}

	return winnersWithSuccessfulPayment, winnersWithUnsuccessfulPayment
}

func (s *OfferProcessingService) createInvoiceForSuccessfulPayment(ctx context.Context, orders []*orderDomain.Order, customerId string) {
	if len(orders) == 0 {
		fmt.Printf("No orders provided for invoice creation for customer %s\n", customerId)
		return
	}

	billingReference, err := s.billingService.GetBillingReferenceByOrderId(ctx, orders[0].OrderId)
	if err != nil {
		fmt.Printf("Error getting billing reference for customer %s: %v\n", customerId, err)
		return
	}

	billing, err := s.billingService.GetBillingById(ctx, billingReference)
	if err != nil {
		fmt.Printf("Error getting billing details for customer %s: %v\n", customerId, err)
		return
	}

	if billing.Customer == nil || billing.InvoiceConfig == nil {
		fmt.Printf("Missing customer or invoice config for billing %s (customer %s)\n", billingReference, customerId)
		return
	}
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

func (s *OfferProcessingService) identifyFailedPaymentWinners(
	allWinners []*orderDomain.Order,
	successfulCustomers []string,
) []*orderDomain.Order {
	successfulMap := make(map[string]bool)
	for _, customerId := range successfulCustomers {
		successfulMap[customerId] = true
	}

	var failedWinners []*orderDomain.Order
	for _, winner := range allWinners {
		if !successfulMap[winner.CustomerId] {
			failedWinners = append(failedWinners, winner)
		}
	}

	return failedWinners
}

func (s *OfferProcessingService) promoteLoserWithFailedPayments(
	ctx context.Context,
	failedWinners []*orderDomain.Order,
	allLosers []*orderDomain.Order,
	itemSpecId string,
) ([]*orderDomain.Order, error) {
	fmt.Printf("\n[Fallback] Promoting losers for ItemSpec: %s\n", itemSpecId)

	freedAvailability := 0
	for _, failed := range failedWinners {
		freedAvailability += failed.TotalQuantity
	}

	fmt.Printf("[Fallback] Freed availability: %d units from %d failed winners\n", freedAvailability, len(failedWinners))

	var itemSpecLosers []*orderDomain.Order
	for _, loser := range allLosers {
		if loser.ItemSpecificationId == itemSpecId && loser.State == "Rejected" {
			itemSpecLosers = append(itemSpecLosers, loser)
		}
	}

	fmt.Printf("[Fallback] Found %d losers for ItemSpec %s\n", len(itemSpecLosers), itemSpecId)

	if len(itemSpecLosers) == 0 {
		fmt.Printf("[Fallback] No losers available to promote\n")
		return nil, nil
	}

	sort.Slice(itemSpecLosers, func(i, j int) bool {
		return itemSpecLosers[i].OfferedAmount > itemSpecLosers[j].OfferedAmount
	})

	var promotedWinners []*orderDomain.Order
	allocatedQuantity := 0

	for _, loser := range itemSpecLosers {
		if allocatedQuantity+loser.TotalQuantity <= freedAvailability {
			promotedWinners = append(promotedWinners, loser)
			allocatedQuantity += loser.TotalQuantity
			fmt.Printf("[Fallback] ✓ Promoting loser %s (Customer: %s, Amount: %d, Quantity: %d)\n",
				loser.OrderId, loser.CustomerId, loser.OfferedAmount, loser.TotalQuantity)
		} else {
			fmt.Printf("[Fallback] ✗ Cannot promote loser %s (needs %d, only %d available)\n",
				loser.OrderId, loser.TotalQuantity, freedAvailability-allocatedQuantity)
		}
	}

	fmt.Printf("[Fallback] Promoted %d losers using %d/%d freed units\n",
		len(promotedWinners), allocatedQuantity, freedAvailability)

	return promotedWinners, nil
}

func (s *OfferProcessingService) updateOrderStatesAfterPromotion(
	ctx context.Context,
	promotedWinners []*orderDomain.Order,
	failedWinners []*orderDomain.Order,
) error {
	fmt.Printf("\n[Fallback] Updating order states after promotion\n")

	for _, promoted := range promotedWinners {
		input := orderDomain.OrderInput{
			OrderId:             promoted.OrderId,
			CustomerId:          promoted.CustomerId,
			ExternalId:          promoted.ExternalId,
			ItemSpecificationId: promoted.ItemSpecificationId,
			State:               "Approved",
			OfferedAmount:       promoted.OfferedAmount,
			IsWinner:            true,
		}
		err := s.orderService.UpdateOrder(ctx, input)
		if err != nil {
			fmt.Printf("[Fallback] Error updating promoted winner %s: %v\n", promoted.OrderId, err)
			return err
		}
		fmt.Printf("[Fallback] ✓ Updated promoted winner %s to Approved\n", promoted.OrderId)
	}

	for _, failed := range failedWinners {
		input := orderDomain.OrderInput{
			OrderId:             failed.OrderId,
			CustomerId:          failed.CustomerId,
			ExternalId:          failed.ExternalId,
			ItemSpecificationId: failed.ItemSpecificationId,
			State:               "Rejected",
			OfferedAmount:       failed.OfferedAmount,
			IsWinner:            false,
		}
		err := s.orderService.UpdateOrder(ctx, input)
		if err != nil {
			fmt.Printf("[Fallback] Error updating failed winner %s: %v\n", failed.OrderId, err)
			return err
		}
		fmt.Printf("[Fallback] ✓ Updated failed winner %s to Rejected\n", failed.OrderId)
	}

	return nil
}
