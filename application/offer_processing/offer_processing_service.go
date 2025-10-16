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

	totalQuantityToReduce := 0
	for _, winner := range winners {
		totalQuantityToReduce += winner.TotalQuantity
	}

	fmt.Printf("\n=== ACTUALIZANDO AVAILABILITY ===\n")
	fmt.Printf("Availability actual: %d\n", availability)
	fmt.Printf("Total quantity a reducir (ganadoras): %d\n", totalQuantityToReduce)

	if itemSpec.IsExternal {
		if totalQuantityToReduce > 0 {
			newStock := availability - totalQuantityToReduce
			fmt.Printf("Calculando nuevo stock EXTERNO: %d - %d = %d\n", availability, totalQuantityToReduce, newStock)
			fmt.Printf("⚠️  ALERTA: newStock = %d %s\n", newStock, func() string {
				if newStock < 0 {
					return "(NEGATIVO - POSIBLE ERROR)"
				}
				return "(OK)"
			}())
			err := s.updateExternalItemStock(ctx, posId, itemSpec.ItemId, newStock)
			if err != nil {
				fmt.Printf("❌ Error updating external stock for item %s: %v\n", itemSpec.ItemId, err)
			} else {
				fmt.Printf("✓ Stock externo actualizado exitosamente a %d\n", newStock)
			}
		}
	} else {
		newAvailability := availability - totalQuantityToReduce
		fmt.Printf("Calculando nuevo availability LOCAL: %d - %d = %d\n", availability, totalQuantityToReduce, newAvailability)
		fmt.Printf("⚠️  ALERTA: newAvailability = %d %s\n", newAvailability, func() string {
			if newAvailability < 0 {
				return "(NEGATIVO - POSIBLE ERROR)"
			}
			return "(OK)"
		}())

		fmt.Printf("Ejecutando itemSpecService.Update con:\n")
		fmt.Printf("  - ItemSpecId: %s\n", itemSpec.Id)
		fmt.Printf("  - Currency: %s\n", itemSpec.Currency)
		fmt.Printf("  - OfferId: %s\n", itemSpec.OfferId)
		fmt.Printf("  - ItemId: %s\n", itemSpec.ItemId)
		fmt.Printf("  - PointOfSaleId: %s\n", itemSpec.PointOfSaleId)
		fmt.Printf("  - Amount: %d\n", itemSpec.Amount)
		fmt.Printf("  - NEW Availability: %d (era %d)\n", newAvailability, itemSpec.Availability)
		fmt.Printf("  - ExpireAt: %v\n", itemSpec.ExpireAt)

		err := s.itemSpecService.Update(ctx, itemSpec.Id, itemSpec.Currency, itemSpec.OfferId, itemSpec.ItemId, itemSpec.PointOfSaleId, itemSpec.Amount, int64(newAvailability), itemSpec.ExpireAt)
		if err != nil {
			fmt.Printf("❌ Error updating item spec availability %s: %v\n", itemSpecId, err)
		} else {
			fmt.Printf("✓ Availability actualizado exitosamente de %d a %d\n", itemSpec.Availability, newAvailability)
		}
	}

	fmt.Printf("=================================\n\n")

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

		for _, order := range customerOrders {
			itemCounts[order.ExtraData] += order.TotalQuantity
			totalOfferedAmount += order.OfferedAmount
		}

		var itemNames []string
		for itemName, totalQuantity := range itemCounts {
			if totalQuantity > 1 {
				itemNames = append(itemNames, fmt.Sprintf("%s x%d unds", itemName, totalQuantity))
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
