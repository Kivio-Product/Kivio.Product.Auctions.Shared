package services

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/billing"
	itemDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
	paymentDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/payment"

	ecommerceService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/ecommerce"
	emailService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/email"
	invoiceService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/invoice"
	pointOfSaleService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/point_of_sale"

	offerService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/offer"
	billingInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/billing"
	itemInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/item"
	itemSpecInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/item_specification"
	orderInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/order"
)

type BillingService interface {
	CreateBilling(ctx context.Context, provider string, customer *domain.Customer, orderIds []string) (*domain.Billing, error)
	GetAllBillings(ctx context.Context) ([]domain.Billing, error)
	GetBillingById(ctx context.Context, id string) (*domain.Billing, error)
	GetAllBillingsWithDetail(ctx context.Context) ([]domain.BillingDetailResponse, error)
	ConfirmPayUResponse(ctx context.Context, res *paymentDomain.ConfirmationResponse, secretKey string) error
	ConfirmWompiResponse(ctx context.Context, body []byte) error
	GetPaginatedBillingsWithDetails(ctx context.Context, params orderDomain.PaginationParams) (*domain.PaginatedBillingDetailsResponse, error)
	GetOrdersBillingByID(ctx context.Context, id string) ([]domain.BillingByOrder, error)
	GetBillingReferenceByOrderId(ctx context.Context, orderId string) (string, error)
}

type billingService struct {
	repo               billingInfrastructure.BillingRepository
	billingFactory     domain.BillingFactory
	orderRepo          orderInfrastructure.OrderRepository
	itemSpecRepo       itemSpecInfrastructure.ItemSpecificationRepository
	itemRepo           itemInfrastructure.ItemRepository
	pointOfSaleService pointOfSaleService.IPosService
	emailService       emailService.EmailServiceInterface
	ecommerceCredSvc   ecommerceService.EcommerceCredentialsService
	ecommerceSvc       ecommerceService.EcommerceService
	offerService       offerService.IOfferService
	invoiceService     invoiceService.InvoiceService
}

func NewBillingService(
	repo billingInfrastructure.BillingRepository,
	billingFactory domain.BillingFactory,
	orderRepo orderInfrastructure.OrderRepository,
	itemSpecRepo itemSpecInfrastructure.ItemSpecificationRepository,
	itemRepo itemInfrastructure.ItemRepository,
	emailService emailService.EmailServiceInterface,
	ecommerceCredSvc ecommerceService.EcommerceCredentialsService,
	ecommerceSvc ecommerceService.EcommerceService,
	offerService offerService.IOfferService,
	pointOfSaleService pointOfSaleService.IPosService,
	invoiceService invoiceService.InvoiceService,
) BillingService {
	return &billingService{
		repo:               repo,
		billingFactory:     billingFactory,
		orderRepo:          orderRepo,
		itemSpecRepo:       itemSpecRepo,
		itemRepo:           itemRepo,
		emailService:       emailService,
		ecommerceCredSvc:   ecommerceCredSvc,
		ecommerceSvc:       ecommerceSvc,
		offerService:       offerService,
		pointOfSaleService: pointOfSaleService,
		invoiceService:     invoiceService,
	}
}

func (s *billingService) CreateBilling(ctx context.Context, provider string, customer *domain.Customer, orderIds []string) (*domain.Billing, error) {

	invoiceConfig := getInvoiceConfigFromEnv()
	billing, err := s.billingFactory.CreateBilling(provider, customer, invoiceConfig)
	if err != nil {
		return nil, err
	}

	order, err := s.orderRepo.GetIdOrder(ctx, orderIds[0])
	if err != nil {
		return nil, err
	}

	if order != nil {
		customerId := order.CustomerId
		billing.CustomerId = &customerId
	} else {
		return nil, fmt.Errorf("no se encontró la orden con ID: %s", orderIds[0])
	}

	err = s.repo.SaveBillingWithOrders(ctx, billing, orderIds)
	if err != nil {
		return nil, err
	}

	return billing, nil
}

func (s *billingService) GetOrdersBillingByID(ctx context.Context, id string) ([]domain.BillingByOrder, error) {
	order, err := s.repo.GetOrdersBillingByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return order, nil
}

func (s *billingService) GetAllBillings(ctx context.Context) ([]domain.Billing, error) {
	billings, err := s.repo.GetAllBillings(ctx)
	if err != nil {
		return nil, err
	}
	return billings, nil
}

func (s *billingService) GetAllBillingsWithDetail(ctx context.Context) ([]domain.BillingDetailResponse, error) {
	billingOrders, err := s.repo.GetAllOrderBillings(ctx)
	if err != nil {
		return nil, err
	}

	billingsMap := make(map[string]*domain.BillingDetailResponse)

	for _, billingOrder := range billingOrders {
		order, err := s.orderRepo.GetIdOrder(ctx, billingOrder.OrderId)
		if err != nil {
			return nil, err
		}

		billing, err := s.repo.GetBillingByID(ctx, billingOrder.BillingId)
		if err != nil {
			return nil, err
		}

		itemSpec, err := s.itemSpecRepo.GetById(ctx, order.ItemSpecificationId)
		if err != nil {
			return nil, err
		}

		var item *itemDomain.Item
		if itemSpec.IsExternal {
			credentials, err := s.ecommerceCredSvc.GetCredentials(ctx, itemSpec.PointOfSaleId)
			if err != nil {
				return nil, fmt.Errorf("error getting ecommerce credentials: %w", err)
			}

			itemId := strings.TrimPrefix(itemSpec.ItemId, "kivio-ecommerce∼")

			item, err = s.ecommerceSvc.GetItemByID(ctx, credentials.ApiURL, credentials.ApiKey, itemId)
			if err != nil {
				return nil, fmt.Errorf("error getting item from ecommerce: %w", err)
			}
		} else {
			item, err = s.itemRepo.GetItemById(ctx, itemSpec.ItemId)
			if err != nil {
				return nil, err
			}
		}

		billOrder := domain.BillOrder{
			OfferId:         order.OfferId,
			ItemName:        item.Name,
			ItemDescription: item.Description,
			OrderAmount:     order.OfferedAmount,
			ItemPrice:       itemSpec.Amount,
		}

		if _, exists := billingsMap[billing.Id]; !exists {
			billingsMap[billing.Id] = &domain.BillingDetailResponse{
				BillId:        billing.Id,
				TransactionId: billing.TransactionId,
				State:         billing.State,
				Provider:      billing.Provider,
				PayloadType:   billing.PayloadType,
				CreatedAt:     billing.CreatedAt,
				ConfirmedAt:   billing.ConfirmedAt,
				UserEmail:     order.CustomerId,
				Orders:        []domain.BillOrder{},
			}
		}

		billingsMap[billing.Id].Orders = append(billingsMap[billing.Id].Orders, billOrder)
	}

	billingDetails := make([]domain.BillingDetailResponse, 0, len(billingsMap))
	for _, detail := range billingsMap {
		billingDetails = append(billingDetails, *detail)
	}

	return billingDetails, nil
}

func (s *billingService) GetPaginatedBillingsWithDetails(ctx context.Context, params orderDomain.PaginationParams) (*domain.PaginatedBillingDetailsResponse, error) {
	if params.PageSize < 1 {
		params.PageSize = 10
	}
	if params.PageSize > 100 {
		params.PageSize = 100
	}

	result, err := s.repo.GetOrderBillingPaginated(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("error al obtener ordenes facturadas paginadas: %w", err)
	}

	billingsMap := make(map[string]*domain.BillingDetailResponse)

	for _, billingOrder := range result.Billings {
		order, err := s.orderRepo.GetIdOrder(ctx, billingOrder.OrderId)
		if err != nil {
			return nil, err
		}

		billing, err := s.repo.GetBillingByID(ctx, billingOrder.BillingId)
		if err != nil {
			return nil, err
		}

		billOrder := domain.BillOrder{
			OfferId:     order.OfferId,
			ItemName:    order.ExtraData,
			OrderAmount: order.OfferedAmount,
		}

		if _, exists := billingsMap[billing.Id]; !exists {
			billingsMap[billing.Id] = &domain.BillingDetailResponse{
				BillId:        billing.Id,
				TransactionId: billing.TransactionId,
				State:         billing.State,
				Provider:      billing.Provider,
				PayloadType:   billing.PayloadType,
				CreatedAt:     billing.CreatedAt,
				ConfirmedAt:   billing.ConfirmedAt,
				UserEmail:     order.CustomerId,
				Orders:        []domain.BillOrder{},
			}
		}

		billingsMap[billing.Id].Orders = append(billingsMap[billing.Id].Orders, billOrder)
	}

	billingDetails := make([]domain.BillingDetailResponse, 0, len(billingsMap))
	for _, detail := range billingsMap {
		billingDetails = append(billingDetails, *detail)
	}

	return &domain.PaginatedBillingDetailsResponse{
		Billings:   billingDetails,
		NextToken:  result.NextToken,
		TotalCount: result.TotalCount,
	}, nil
}

func (s *billingService) GetBillingById(ctx context.Context, id string) (*domain.Billing, error) {
	billing, err := s.repo.GetBillingByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return billing, nil
}

func (s *billingService) GetOrdersByBillingId(ctx context.Context, id string) ([]domain.BillingByOrder, error) {
	billing, err := s.repo.GetOrdersBillingByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return billing, nil
}

func (s *billingService) GetBillingReferenceByOrderId(ctx context.Context, orderId string) (string, error) {
	billingsByOrder, err := s.repo.GetAllOrderBillings(ctx)
	if err != nil {
		return "", fmt.Errorf("error obteniendo BillingByOrder: %w", err)
	}

	for _, billingOrder := range billingsByOrder {
		if billingOrder.OrderId == orderId {
			return billingOrder.BillingId, nil
		}
	}

	return "", fmt.Errorf("no se encontró billing para el orderId: %s", orderId)
}

func (s *billingService) ConfirmPayUResponse(ctx context.Context, res *paymentDomain.ConfirmationResponse, secretKey string) error {
	fmt.Println("Iniciando ConfirmPayUResponse")

	if res == nil || res.ReferenceSale == "" {
		fmt.Println("Error: confirmación nula o referencia de venta vacía")
		return errors.New("referencia inválida")
	}

	fmt.Printf("Datos de confirmación: MerchantId=%s, ReferenceSale=%s, Value=%s, Currency=%s, StatePol=%d\n",
		res.MerchantId, res.ReferenceSale, res.ValueStr, res.Currency, res.StatePol)

	isValid := validatePayUSignature(secretKey, res.MerchantId, res.ReferenceSale, res.ValueStr, res.Currency, res.StatePol, res.Sign)
	if !isValid {
		fmt.Printf("Error: firma inválida para transacción %s\n", res.ReferenceSale)
		return errors.New("firma inválida")
	}

	fmt.Println("Firma validada correctamente")

	billingId := res.ReferenceSale
	fmt.Printf("Buscando facturación con ID: %s\n", billingId)

	billing, err := s.repo.GetBillingByID(ctx, billingId)
	if err != nil {
		fmt.Printf("Error: no se encontró facturación con ID: %s - %v\n", billingId, err)
		return fmt.Errorf("no se encontró facturación con ID: %s", billingId)
	}

	fmt.Printf("Facturación encontrada: %+v\n", billing)

	state := map[int]string{
		4:   "Approved",
		6:   "Rejected",
		104: "Error",
		7:   "Pending",
	}[res.StatePol]

	fmt.Printf("Estado de la transacción: %d -> %s\n", res.StatePol, state)

	billing.State = state
	billing.PayloadType = res.PaymentMethod
	billing.TransactionId = res.TransactionId
	billing.ConfirmedAt = time.Now()

	fmt.Printf("Actualizando facturación: State=%s, PayloadType=%s, TransactionId=%s, ConfirmedAt=%v\n",
		billing.State, billing.PayloadType, billing.TransactionId, billing.ConfirmedAt)

	err = s.repo.UpdateBilling(ctx, billing)
	if err != nil {
		fmt.Printf("Error al actualizar la facturación: %v\n", err)
		return fmt.Errorf("error al actualizar la facturación: %v", err)
	}

	orders, err := s.repo.GetOrdersBillingByID(ctx, billingId)
	if err != nil {
		fmt.Printf("no se encontraron ordenes de facturas con ID: %s\n", billingId)
		return fmt.Errorf("no se encontraron ordenes de facturas con ID: %s", billingId)
	}

	var orderIDs []string
	for _, order := range orders {
		orderIDs = append(orderIDs, order.OrderId)
	}

	var validOrders []*orderDomain.Order
	for _, id := range orderIDs {
		order, err := s.orderRepo.GetIdOrder(ctx, id)
		if err == nil {
			validOrders = append(validOrders, order)
		}
	}

	if len(validOrders) == 0 {
		return fmt.Errorf("no se encontró ninguna orden válida en: %v", orderIDs)
	}

	var posId = validOrders[0].PointOfSaleId

	var posName string
	if posId != "" {
		pos, err := s.pointOfSaleService.GetPosById(ctx, posId)
		if err == nil {
			posName = pos.Name
		}
	}

	var concatenatedItemNames []string
	var concatenatedItemDescriptions []string
	var concatenatedItemSpecsAvailability []int64
	var firstOrderAmount int64
	var customerEmail string
	var offerId string

	if res.Extra1 == "Quick offer" {
		for _, order := range validOrders {
			itemSpec, err := s.itemSpecRepo.GetById(ctx, order.ItemSpecificationId)
			if err != nil {
				fmt.Printf("no se encontro el itemSpec con Id: %s\n", order.ItemSpecificationId)
				continue
			}
			concatenatedItemNames = append(concatenatedItemNames, order.ExtraData)

			var item *itemDomain.Item
			if itemSpec.IsExternal {
				credentials, err := s.ecommerceCredSvc.GetCredentials(ctx, itemSpec.PointOfSaleId)
				if err != nil {
					fmt.Printf("error getting ecommerce credentials: %v\n", err)
					continue
				}

				itemId := strings.TrimPrefix(itemSpec.ItemId, "kivio-ecommerce∼")
				item, err = s.ecommerceSvc.GetItemByID(ctx, credentials.ApiURL, credentials.ApiKey, itemId)
				if err != nil {
					fmt.Printf("error getting item from ecommerce: %v\n", err)
					continue
				}
			} else {
				item, err = s.itemRepo.GetItemById(ctx, itemSpec.ItemId)
				if err != nil {
					fmt.Printf("no se encontro el item con Id: %s\n", itemSpec.ItemId)
					continue
				}
			}

			if item != nil {
				concatenatedItemDescriptions = append(concatenatedItemDescriptions, item.Description)
			}
			if firstOrderAmount == 0 {
				firstOrderAmount = order.OfferedAmount
			}
			if customerEmail == "" {
				customerEmail = order.CustomerId
			}

			if offerId == "" {
				offerId = order.OfferId
			}
			switch state {
			case "Approved":
				order.State = "Approved"
				itemSpec.Availability--
				if itemSpec.IsExternal && item != nil {
					credentials, err := s.ecommerceCredSvc.GetCredentials(ctx, order.PointOfSaleId)
					if err == nil {
						itemId := strings.TrimPrefix(itemSpec.ItemId, "kivio-ecommerce∼")
						itemRaw, err := s.ecommerceSvc.GetItemByIDRaw(ctx, itemId, credentials.ApiURL, credentials.ApiKey)
						if err == nil && itemRaw != nil {
							type externalProductResponse struct {
								Products []struct {
									StockQuantity int64 `json:"stock_quantity"`
								} `json:"products"`
							}
							var extResp externalProductResponse
							if err := json.Unmarshal(itemRaw, &extResp); err == nil && len(extResp.Products) > 0 {
								stock := extResp.Products[0].StockQuantity
								if stock > 0 {
									fmt.Printf("Actualizando stock del item %s: %d -> %d\n", itemId, stock, stock-1)
									_ = s.ecommerceSvc.UpdateItemStock(ctx, credentials.ApiURL, credentials.ApiKey, itemId, int(stock-1))
								}
							}
						}
					}
				}
			case "Rejected", "Error":
				order.State = "Rejected"
			default:
				continue
			}

			if itemSpec != nil {
				concatenatedItemSpecsAvailability = append(concatenatedItemSpecsAvailability, itemSpec.Availability)
			}

			err = s.orderRepo.UpdateOrder(ctx, order)
			if err != nil {
				return fmt.Errorf("no se pudo actualizar la orden %s: %v", order.OrderId, err)
			}

			err = s.itemSpecRepo.UpdateItemSpec(ctx, itemSpec)
			if err != nil {
				return fmt.Errorf("no se pudo actualizar el item specification %s: %v", order.ItemSpecificationId, err)
			}
		}

		allZero := true
		for _, availability := range concatenatedItemSpecsAvailability {
			if availability != 0 {
				allZero = false
				break
			}
		}

		if allZero {
			err = s.offerService.UpdateOfferState(ctx, offerId, "Closed")
			if err != nil {
				return fmt.Errorf("no se pudo actualizar ela oferta %s: %v", offerId, err)
			}
		}

		if customerEmail != "" && len(concatenatedItemNames) > 0 {
			go func() {
				err = s.emailService.NotifyOrder(ctx, state, customerEmail, firstOrderAmount, strings.Join(concatenatedItemNames, ", "), posName)
				if err != nil {
					fmt.Printf("No se puedo enviar el correo: %s\n", err)
				}
			}()
		}

		if state == "Approved" && len(validOrders) > 0 {
			go s.createInvoiceForApprovedPayment(ctx, billingId, validOrders, posName)
		}
	}

	if res.Extra1 == "Regular auction" {
		for _, order := range validOrders {
			if customerEmail == "" && len(validOrders) > 0 {
				customerEmail = validOrders[0].CustomerId
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
				return fmt.Errorf("no se pudo actualizar la orden %s: %v", order.OrderId, err)
			}
		}
		if customerEmail != "" && len(concatenatedItemNames) > 0 {
			go func() {
				err = s.emailService.NotifyOrder(ctx, state, customerEmail, firstOrderAmount, strings.Join(concatenatedItemNames, ", "), posName)
				if err != nil {
					fmt.Printf("No se puedo enviar el correo: %s\n", err)
				}
			}()
		}

		if state == "Approved" && len(validOrders) > 0 {
			go s.createInvoiceForApprovedPayment(ctx, billingId, validOrders, posName)
		}
	}

	fmt.Println("Facturación actualizada correctamente")
	return nil
}

func (s *billingService) createInvoiceForApprovedPayment(ctx context.Context, billingId string, orders []*orderDomain.Order, posName string) {
	if len(orders) == 0 {
		fmt.Printf("No orders provided for invoice creation for billing %s\n", billingId)
		return
	}

	billing, err := s.GetBillingById(ctx, billingId)
	if err != nil {
		fmt.Printf("Error getting billing details for %s: %v\n", billingId, err)
		return
	}

	if billing.Customer == nil || billing.InvoiceConfig == nil {
		fmt.Printf("Missing customer or invoice config for billing %s\n", billingId)
		return
	}

	invoiceCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	fmt.Printf("DEBUG: Creating invoice with new context for billing %s\n", billingId)

	_, err = s.invoiceService.CreateInvoiceForOrders(invoiceCtx, billingId, orders, billing.Customer, billing.InvoiceConfig, posName)
	if err != nil {
		fmt.Printf("Error creating invoice for billing %s: %v\n", billingId, err)
		return
	}

	fmt.Printf("Invoice created successfully for billing %s with %d orders\n", billingId, len(orders))
}

type WompiWebhook struct {
	Event string `json:"event"`
	Data  struct {
		Transaction struct {
			ID            string `json:"id"`
			AmountInCents int64  `json:"amount_in_cents"`
			Reference     string `json:"reference"`
			CustomerEmail string `json:"customer_email"`
			Currency      string `json:"currency"`
			PaymentMethod string `json:"payment_method_type"`
			RedirectURL   string `json:"redirect_url"`
			Status        string `json:"status"`
		} `json:"transaction"`
	} `json:"data"`
	Environment string `json:"environment"`
	Signature   struct {
		Properties []string `json:"properties"`
		Checksum   string   `json:"checksum"`
	} `json:"signature"`
	Timestamp int64  `json:"timestamp"`
	SentAt    string `json:"sent_at"`
}

func (s *billingService) ConfirmWompiResponse(ctx context.Context, body []byte) error {
	fmt.Println("Iniciando ConfirmWompiResponse")

	var webhook WompiWebhook
	if err := json.Unmarshal(body, &webhook); err != nil {
		return fmt.Errorf("error al parsear el body de Wompi: %w", err)
	}

	tx := webhook.Data.Transaction
	billingId := tx.Reference

	fmt.Printf("Buscando facturación con ID: %s\n", billingId)
	billing, err := s.repo.GetBillingByID(ctx, billingId)
	if err != nil {
		fmt.Printf("Error: no se encontró facturación con ID: %s - %v\n", billingId, err)
		return fmt.Errorf("no se encontró facturación con ID: %s", billingId)
	}

	fmt.Printf("Facturación encontrada: %+v\n", billing)

	state := map[string]string{
		"APPROVED": "Approved",
		"DECLINED": "Rejected",
		"PENDING":  "Pending",
		"VOIDED":   "Error",
		"ERROR":    "Error",
	}[strings.ToUpper(tx.Status)]

	fmt.Printf("Estado de la transacción: %s -> %s\n", tx.Status, state)

	billing.State = state
	billing.PayloadType = tx.PaymentMethod
	billing.TransactionId = tx.ID
	billing.ConfirmedAt = time.Now()

	fmt.Printf("Actualizando facturación: State=%s, PayloadType=%s, TransactionId=%s, ConfirmedAt=%v\n",
		billing.State, billing.PayloadType, billing.TransactionId, billing.ConfirmedAt)

	err = s.repo.UpdateBilling(ctx, billing)
	if err != nil {
		fmt.Printf("Error al actualizar la facturación: %v\n", err)
		return fmt.Errorf("error al actualizar la facturación: %v", err)
	}

	orders, err := s.repo.GetOrdersBillingByID(ctx, billingId)
	if err != nil {
		fmt.Printf("no se encontraron ordenes de facturas con ID: %s\n", billingId)
		return fmt.Errorf("no se encontraron ordenes de facturas con ID: %s", billingId)
	}

	var orderIDs []string
	for _, order := range orders {
		orderIDs = append(orderIDs, order.OrderId)
	}

	var validOrders []*orderDomain.Order
	for _, id := range orderIDs {
		order, err := s.orderRepo.GetIdOrder(ctx, id)
		if err == nil {
			validOrders = append(validOrders, order)
		}
	}

	if len(validOrders) == 0 {
		return fmt.Errorf("no se encontró ninguna orden válida en: %v", orderIDs)
	}

	var posId = validOrders[0].PointOfSaleId

	var posName string
	if posId != "" {
		pos, err := s.pointOfSaleService.GetPosById(ctx, posId)
		if err == nil {
			posName = pos.Name
		}
	}

	var concatenatedItemNames []string
	var firstOrderAmount int64
	var customerEmail string

	for _, order := range validOrders {
		if customerEmail == "" && len(validOrders) > 0 {
			customerEmail = validOrders[0].CustomerId
		}

		switch state {
		case "Approved":
			order.State = "Approved"
		case "Rejected", "Error":
			order.State = "Rejected"
		default:
			continue
		}

		err := s.orderRepo.UpdateOrder(ctx, order)
		if err != nil {
			return fmt.Errorf("no se pudo actualizar la orden %s: %v", order.OrderId, err)
		}

		concatenatedItemNames = append(concatenatedItemNames, order.ExtraData)
		if firstOrderAmount == 0 {
			firstOrderAmount = order.OfferedAmount
		}
	}

	if customerEmail != "" && len(concatenatedItemNames) > 0 {
		go func() {
			err = s.emailService.NotifyOrder(ctx, state, customerEmail, firstOrderAmount, strings.Join(concatenatedItemNames, ", "), posName)
			if err != nil {
				fmt.Printf("No se pudo enviar el correo: %s\n", err)
			}
		}()
	}

	if state == "Approved" && len(validOrders) > 0 {
		go s.createInvoiceForApprovedPayment(ctx, billingId, validOrders, posName)
	}

	fmt.Println("Facturación actualizada correctamente (Wompi)")
	return nil
}

func validatePayUSignature(secretKey, merchantId, referenceSale string, valueStr string, currency string, statePol int, incomingSignature string) bool {

	value, _ := strconv.ParseFloat(valueStr, 64)
	fmt.Printf("Valor original: %s, Convertido a float: %f\n", valueStr, value)

	var formattedValue string
	if math.Mod(value*100, 10) == 0 {
		formattedValue = fmt.Sprintf("%.1f", value)
	} else {
		formattedValue = fmt.Sprintf("%.2f", value)
	}

	fmt.Printf("Valor formateado: %s\n", formattedValue)

	signatureString := fmt.Sprintf("%s~%s~%s~%s~%s~%d",
		secretKey, merchantId, referenceSale, formattedValue, currency, statePol)

	fmt.Printf("String para firma (ocultando clave secreta): [SECRET]~%s~%s~%s~%s~%d\n",
		merchantId, referenceSale, formattedValue, currency, statePol)

	hash := md5.Sum([]byte(signatureString))
	expected := hex.EncodeToString(hash[:])

	fmt.Printf("Firma esperada: %s\n", expected)
	fmt.Printf("Firma recibida: %s\n", incomingSignature)
	fmt.Printf("¿Las firmas coinciden? %t\n", strings.EqualFold(expected, incomingSignature))

	return strings.EqualFold(expected, incomingSignature)
}

func getInvoiceConfigFromEnv() *domain.InvoiceConfig {
	documentIDStr := os.Getenv("INVOICE_DOCUMENT_ID")
	sellerIDStr := os.Getenv("INVOICE_SELLER_ID")
	paymentIDStr := os.Getenv("INVOICE_PAYMENT_ID")

	documentID, _ := strconv.Atoi(documentIDStr)
	sellerID, _ := strconv.Atoi(sellerIDStr)
	paymentID, _ := strconv.Atoi(paymentIDStr)

	return &domain.InvoiceConfig{
		DocumentID: documentID,
		SellerID:   sellerID,
		PaymentID:  paymentID,
	}
}
