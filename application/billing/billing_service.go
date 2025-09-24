package services

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
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

	customerService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/customer"
	ecommerceService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/ecommerce"
	emailService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/email"
	invoiceService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/invoice"
	pointOfSaleService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/point_of_sale"
	ecommerceInfra "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/ecommerce"

	offerService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/offer"
	billingInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/billing"
	itemInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/item"
	itemSpecInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/item_specification"
	orderInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/order"
)

type BillingService interface {
	CreateBilling(ctx context.Context, provider, posId, customerId string, customer *domain.Customer) (*domain.Billing, error)
	GetAllBillings(ctx context.Context) ([]domain.Billing, error)
	GetBillingById(ctx context.Context, id string) (*domain.Billing, error)
	ConfirmPayUResponse(ctx context.Context, res *paymentDomain.ConfirmationResponse, secretKey string) error
	ConfirmWompiResponse(ctx context.Context, body []byte) error
	GetPaginatedBillingsWithDetails(ctx context.Context, params orderDomain.PaginationParams, filters map[string]string) (*domain.PaginatedBillingDetailsResponse, error)
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
	customerService    customerService.CustomerService
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
	customerService customerService.CustomerService,
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
		customerService:    customerService,
	}
}

func (s *billingService) CreateBilling(ctx context.Context, provider, posId, customerId string, customer *domain.Customer) (*domain.Billing, error) {
	invoiceConfig := getInvoiceConfigFromEnv()
	billing, err := s.billingFactory.CreateBilling(provider, posId, customer, invoiceConfig)
	if err != nil {
		return nil, err
	}

	if err != nil {
		return nil, err
	}

	billing.CustomerId = &customerId

	err = s.repo.SaveBilling(ctx, billing)

	if err != nil {
		return nil, err
	}

	return billing, nil
}

func (s *billingService) GetAllBillings(ctx context.Context) ([]domain.Billing, error) {
	billings, err := s.repo.GetAllBillings(ctx)
	if err != nil {
		return nil, err
	}
	return billings, nil
}

func (s *billingService) GetPaginatedBillingsWithDetails(ctx context.Context, params orderDomain.PaginationParams, filters map[string]string) (*domain.PaginatedBillingDetailsResponse, error) {
	if params.PageSize < 1 {
		params.PageSize = 10
	}
	if params.PageSize > 100 {
		params.PageSize = 100
	}

	result, err := s.repo.GetOrderBillingPaginated(ctx, params, filters)
	if err != nil {
		return nil, fmt.Errorf("error al obtener ordenes facturadas paginadas: %w", err)
	}

	billingsMap := make(map[string]*domain.BillingDetailResponse)

	for _, billing := range result.Billings {

		orders, _ := s.orderRepo.GetOrdersBillingByID(ctx, billing.Id)

		if _, exists := billingsMap[billing.Id]; !exists {
			billingsMap[billing.Id] = &domain.BillingDetailResponse{
				BillId:        billing.Id,
				TransactionId: billing.TransactionId,
				State:         billing.State,
				Provider:      billing.Provider,
				PayloadType:   billing.PayloadType,
				CreatedAt:     billing.CreatedAt,
				ConfirmedAt:   billing.ConfirmedAt,
				UserEmail:     *billing.CustomerId,
				Orders:        []domain.BillOrder{},
			}
		}

		for _, order := range orders {
			billOrder := domain.BillOrder{
				OfferId:     order.OfferId,
				ItemName:    order.ExtraData,
				OrderAmount: order.OfferedAmount,
			}

			billingsMap[billing.Id].Orders = append(billingsMap[billing.Id].Orders, billOrder)
		}
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

func (s *billingService) GetBillingReferenceByOrderId(ctx context.Context, orderId string) (string, error) {
	order, err := s.orderRepo.GetIdOrder(ctx, orderId)
	if err != nil {
		return "", fmt.Errorf("error obteniendo Order: %w", err)
	}

	if order.BillingId != "" {
		return order.BillingId, nil
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

	orders, err := s.orderRepo.GetOrdersBillingByID(ctx, billingId)
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
			firstOrderAmount += int64(order.OfferedAmount)

			var item *itemDomain.Item
			if itemSpec.IsExternal {
				credentials, err := s.ecommerceCredSvc.GetCredentials(ctx, itemSpec.PointOfSaleId)
				if err != nil {
					fmt.Printf("error getting ecommerce credentials: %v\n", err)
					continue
				}

				itemId := strings.TrimPrefix(itemSpec.ItemId, "kivio-ecommerce∼")
				item, err = s.ecommerceSvc.GetItemByID(ctx, itemId, credentials.ApiURL, credentials.ApiKey)
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
			if customerEmail == "" {
				customerEmail = order.CustomerId
			}

			if offerId == "" {
				offerId = order.OfferId
			}
			switch state {
			case "Approved":
				fmt.Printf("[DEBUG] Orden aprobada, estado: %s\n", state)
				order.State = "Approved"
				itemSpec.Availability--
				fmt.Printf("[DEBUG] itemSpec.IsExternal: %v, item != nil: %v\n", itemSpec.IsExternal, item != nil)
				if itemSpec.IsExternal && item != nil {
					fmt.Printf("[DEBUG] Obteniendo credenciales para PointOfSaleId: %s\n", order.PointOfSaleId)
					credentials, err := s.ecommerceCredSvc.GetCredentials(ctx, order.PointOfSaleId)
					if err == nil {
						fmt.Printf("[DEBUG] Credenciales obtenidas exitosamente, creando customer y orden en ecommerce\n")
						creds := &struct {
							ApiURL string
							ApiKey string
						}{
							ApiURL: credentials.ApiURL,
							ApiKey: credentials.ApiKey,
						}

						fmt.Printf("[DEBUG] Llamando createEcommerceCustomerAndOrder...\n")
						err = s.createEcommerceCustomerAndOrder(ctx, credentials.ApiURL, credentials.ApiKey, billing, validOrders, item, creds)
						if err != nil {
							fmt.Printf("Error creando customer y orden en ecommerce: %v\n", err)
						} else {
							fmt.Printf("[DEBUG] createEcommerceCustomerAndOrder ejecutado exitosamente\n")
						}
					} else {
						fmt.Printf("[DEBUG] Error obteniendo credenciales: %v\n", err)
					}
				} else {
					fmt.Printf("[DEBUG] Condición no cumplida - itemSpec.IsExternal: %v, item != nil: %v\n", itemSpec.IsExternal, item != nil)
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
				err = s.emailService.NotifyOrder(ctx, state, customerEmail, firstOrderAmount, strings.Join(concatenatedItemNames, ", "), posName, "")
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
				err = s.emailService.NotifyOrder(ctx, state, customerEmail, firstOrderAmount, strings.Join(concatenatedItemNames, ", "), posName, "")
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

	isValid := validateWompiEventSignature(&webhook)
	if !isValid {
		fmt.Printf("Error: firma inválida para evento Wompi con ID: %s\n", webhook.Data.Transaction.ID)
		return errors.New("firma del evento inválida")
	}

	fmt.Println("Firma del evento validada correctamente")

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

	orders, err := s.orderRepo.GetOrdersBillingByID(ctx, billingId)
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

		fmt.Printf("[DEBUG]: wompi state %s\n", state)

		switch state {
		case "Approved":
			fmt.Printf("[DEBUG 2] Orden aprobada, estado: %s\n", state)
			order.State = "Approved"

			fmt.Printf("[DEBUG 2] Obteniendo itemSpec para ItemSpecificationId: %s\n", order.ItemSpecificationId)
			itemSpec, err := s.itemSpecRepo.GetById(ctx, order.ItemSpecificationId)
			if err == nil && itemSpec.IsExternal {
				fmt.Printf("[DEBUG 2] itemSpec obtenido, IsExternal: %v\n", itemSpec.IsExternal)
				var item *itemDomain.Item
				fmt.Printf("[DEBUG 2] Obteniendo credenciales para PointOfSaleId: %s\n", itemSpec.PointOfSaleId)
				credentials, err := s.ecommerceCredSvc.GetCredentials(ctx, itemSpec.PointOfSaleId)
				if err == nil {
					fmt.Printf("[DEBUG 2] Credenciales obtenidas, obteniendo item con ID: %s\n", itemSpec.ItemId)
					itemId := strings.TrimPrefix(itemSpec.ItemId, "kivio-ecommerce∼")
					fmt.Printf("[DEBUG 2] ItemId procesado: %s\n", itemId)
					item, err = s.ecommerceSvc.GetItemByID(ctx, itemId, credentials.ApiURL, credentials.ApiKey)
					if err == nil && item != nil {
						fmt.Printf("[DEBUG 2] Item obtenido exitosamente, llamando createEcommerceCustomerAndOrder...\n")
						creds := &struct {
							ApiURL string
							ApiKey string
						}{
							ApiURL: credentials.ApiURL,
							ApiKey: credentials.ApiKey,
						}

						err = s.createEcommerceCustomerAndOrder(ctx, credentials.ApiURL, credentials.ApiKey, billing, validOrders, item, creds)
						if err != nil {
							fmt.Printf("Error creando customer y orden en ecommerce: %v\n", err)
						} else {
							fmt.Printf("[DEBUG 2] createEcommerceCustomerAndOrder ejecutado exitosamente\n")
						}
					} else {
						fmt.Printf("[DEBUG 2] Error obteniendo item o item es nil - Error: %v, Item: %v\n", err, item)
					}
				} else {
					fmt.Printf("[DEBUG 2] Error obteniendo credenciales: %v\n", err)
				}
			} else {
				fmt.Printf("[DEBUG 2] itemSpec no encontrado o no es externo - Error: %v, IsExternal: %v\n", err, itemSpec != nil && itemSpec.IsExternal)
			}

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
			err = s.emailService.NotifyOrder(ctx, state, customerEmail, firstOrderAmount, strings.Join(concatenatedItemNames, ", "), posName, "")
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

func validateWompiEventSignature(webhook *WompiWebhook) bool {
	eventSecret := os.Getenv("WOMPI_EVENT_SECRET")
	if eventSecret == "" {
		fmt.Println("Error: WOMPI_EVENT_SECRET no está configurado")
		return false
	}

	tx := webhook.Data.Transaction

	fmt.Printf("=== DEBUG WOMPI SIGNATURE VALIDATION ===\n")
	fmt.Printf("Transaction ID: '%s'\n", tx.ID)
	fmt.Printf("Transaction Status: '%s'\n", tx.Status)
	fmt.Printf("Transaction Amount: '%d'\n", tx.AmountInCents)
	fmt.Printf("Timestamp: '%d'\n", webhook.Timestamp)
	fmt.Printf("Event Secret: '%s'\n", eventSecret)

	signatureString := tx.ID + tx.Status + strconv.FormatInt(tx.AmountInCents, 10) + strconv.FormatInt(webhook.Timestamp, 10) + eventSecret

	fmt.Printf("Signature String Completo: '%s'\n", signatureString)
	fmt.Printf("Signature String (ocultando secret): '%s'\n", strings.Replace(signatureString, eventSecret, "[EVENT_SECRET]", -1))

	hash := sha256.Sum256([]byte(signatureString))
	expected := hex.EncodeToString(hash[:])

	fmt.Printf("Firma esperada (SHA256): %s\n", expected)
	fmt.Printf("Firma recibida (checksum): %s\n", webhook.Signature.Checksum)
	fmt.Printf("¿Las firmas coinciden? %t\n", strings.EqualFold(expected, webhook.Signature.Checksum))
	fmt.Printf("========================================\n")

	return strings.EqualFold(expected, webhook.Signature.Checksum)
}

func getInvoiceConfigFromEnv() *domain.InvoiceConfig {
	documentIDStr := os.Getenv("INVOICE_DOCUMENT_ID")
	sellerIDStr := os.Getenv("INVOICE_SELLER_ID")
	paymentIDStr := os.Getenv("INVOICE_PAYMENT_ID")
	taxIDStr := os.Getenv("INVOICE_TAX_ID")

	documentID, _ := strconv.Atoi(documentIDStr)
	sellerID, _ := strconv.Atoi(sellerIDStr)
	paymentID, _ := strconv.Atoi(paymentIDStr)
	taxID, _ := strconv.Atoi(taxIDStr)

	return &domain.InvoiceConfig{
		DocumentID: documentID,
		SellerID:   sellerID,
		PaymentID:  paymentID,
		TaxID:      taxID,
	}
}

func (s *billingService) createEcommerceCustomerFromBilling(billing *domain.Billing) *ecommerceInfra.EcommerceCustomer {
	now := time.Now()

	customer := &ecommerceInfra.EcommerceCustomer{
		Username:     "",
		Email:        billing.Customer.Email,
		FirstName:    "",
		LastName:     "",
		Active:       true,
		CreatedOnUTC: now,
		RoleIDs:      []int{4},
	}

	if len(billing.Customer.Name) > 0 {
		if len(billing.Customer.Name) > 1 {
			customer.FirstName = billing.Customer.Name[0]
			customer.LastName = strings.Join(billing.Customer.Name[1:], " ")
		} else {
			fullName := billing.Customer.Name[0]
			nameParts := strings.Fields(strings.TrimSpace(fullName))
			if len(nameParts) > 1 {
				customer.FirstName = nameParts[0]
				customer.LastName = strings.Join(nameParts[1:], " ")
			} else {
				customer.FirstName = fullName
				customer.LastName = ""
			}
		}
	}

	return customer
}

func (s *billingService) createEcommerceBillingAddressFromBilling(billing *domain.Billing) *ecommerceInfra.EcommerceAddress {
	now := time.Now()

	firstName := ""
	lastName := ""

	if len(billing.Customer.Name) > 0 {
		if len(billing.Customer.Name) > 1 {
			firstName = billing.Customer.Name[0]
			lastName = strings.Join(billing.Customer.Name[1:], " ")
		} else {
			fullName := billing.Customer.Name[0]
			nameParts := strings.Fields(strings.TrimSpace(fullName))
			if len(nameParts) > 1 {
				firstName = nameParts[0]
				lastName = strings.Join(nameParts[1:], " ")
			} else {
				firstName = fullName
				lastName = ""
			}
		}
	}

	address := &ecommerceInfra.EcommerceAddress{
		FirstName:     firstName,
		LastName:      lastName,
		Email:         billing.Customer.Email,
		City:          billing.Customer.Address.City.CityName,
		Address1:      billing.Customer.Address.Address,
		ZipPostalCode: billing.Customer.Address.PostalCode,
		Country:       billing.Customer.Address.City.CountryName,
		Province:      billing.Customer.Address.City.StateName,
		CreatedOnUTC:  now,
		CountryID:     57,
	}

	if len(billing.Customer.Phones) > 0 {
		address.PhoneNumber = billing.Customer.Phones[0].Indicative + billing.Customer.Phones[0].Number
	}

	return address
}

func (s *billingService) createEcommerceShippingAddressFromBilling(billing *domain.Billing) *ecommerceInfra.EcommerceAddress {
	now := time.Now()

	firstName := ""
	lastName := ""

	if len(billing.Customer.Name) > 0 {
		if len(billing.Customer.Name) > 1 {
			firstName = billing.Customer.Name[0]
			lastName = strings.Join(billing.Customer.Name[1:], " ")
		} else {
			fullName := billing.Customer.Name[0]
			nameParts := strings.Fields(strings.TrimSpace(fullName))
			if len(nameParts) > 1 {
				firstName = nameParts[0]
				lastName = strings.Join(nameParts[1:], " ")
			} else {
				firstName = fullName
				lastName = ""
			}
		}
	}

	var addressInfo domain.CustomerAddress
	if billing.Customer.ShippingAddress != nil {
		addressInfo = *billing.Customer.ShippingAddress
		fmt.Printf("Using customer shipping address: %+v\n", addressInfo)
	} else {
		addressInfo = billing.Customer.Address
		fmt.Printf("Using customer billing address as fallback for shipping: %+v\n", addressInfo)
	}

	address := &ecommerceInfra.EcommerceAddress{
		FirstName:     firstName,
		LastName:      lastName,
		Email:         billing.Customer.Email,
		City:          addressInfo.City.CityName,
		Address1:      addressInfo.Address,
		ZipPostalCode: addressInfo.PostalCode,
		Country:       addressInfo.City.CountryName,
		Province:      addressInfo.City.StateName,
		CreatedOnUTC:  now,
		CountryID:     57,
	}

	if len(billing.Customer.Phones) > 0 {
		address.PhoneNumber = billing.Customer.Phones[0].Indicative + billing.Customer.Phones[0].Number
	}

	return address
}

func (s *billingService) createEcommerceOrderFromOrders(orders []*orderDomain.Order, customerID int, item *itemDomain.Item) *ecommerceInfra.EcommerceOrder {
	now := time.Now()
	totalAmount := float64(0)

	var orderItems []ecommerceInfra.EcommerceOrderItem
	for _, order := range orders {
		itemAmount := float64(order.OfferedAmount) / 100.0
		totalAmount += itemAmount

		orderItem := ecommerceInfra.EcommerceOrderItem{
			Quantity:         1,
			UnitPriceInclTax: itemAmount,
			UnitPriceExclTax: itemAmount,
			PriceInclTax:     itemAmount,
			PriceExclTax:     itemAmount,
		}
		orderItems = append(orderItems, orderItem)
	}

	customerEmail := ""
	if len(orders) > 0 {
		customerEmail = orders[0].CustomerId
	}

	address := &ecommerceInfra.EcommerceAddress{
		FirstName:    "Cliente",
		LastName:     "Kivio",
		Email:        customerEmail,
		City:         "Bogotá",
		Address1:     "Dirección del cliente",
		Country:      "Colombia",
		CreatedOnUTC: now,
	}

	order := &ecommerceInfra.EcommerceOrder{
		StoreID:                 1,
		PaymentMethodSystemName: "Payments.Manual",
		CustomerCurrencyCode:    "COP",
		CurrencyRate:            1.0,
		OrderSubtotalInclTax:    totalAmount,
		OrderSubtotalExclTax:    totalAmount,
		OrderTotal:              totalAmount,
		CreatedOnUTC:            now,
		CustomerID:              customerID,
		BillingAddress:          address,
		ShippingAddress:         address,
		OrderItems:              orderItems,
	}

	return order
}

func (s *billingService) createEcommerceCustomerAndOrder(ctx context.Context, credentialsApiURL string, credentialsApiKey string, billing *domain.Billing, orders []*orderDomain.Order, item *itemDomain.Item, credentials interface{}) error {
	fmt.Printf("[BILLING] Starting ecommerce customer & order creation - Email: %s, Orders: %d\n", billing.Customer.Email, len(orders))

	customer, err := s.customerService.GetOrCreateCustomer(ctx, billing.Customer.Email)
	if err != nil {
		fmt.Printf("Error getting or creating customer: %v\n", err)
		return fmt.Errorf("error getting or creating customer: %v", err)
	}

	var customerResponse *ecommerceInfra.EcommerceCustomerResponse
	var billingAddressResponse *ecommerceInfra.EcommerceBillingAddressResponse

	if customer.ExternalCustomerID == "" {
		ecommerceCustomer := s.createEcommerceCustomerFromBilling(billing)

		fmt.Printf("Creando customer en ecommerce: %+v\n", ecommerceCustomer)

		customerResponse, err = s.ecommerceSvc.CreateEcommerceCustomer(ctx, credentialsApiURL, credentialsApiKey, ecommerceCustomer)
		if err != nil {
			fmt.Printf("Error creando customer en ecommerce: %v\n", err)
			return fmt.Errorf("error creando customer en ecommerce: %v", err)
		}

		fmt.Printf("Customer creado exitosamente con ID: %d\n", customerResponse.ID)

		err = s.customerService.UpdateExternalCustomerID(ctx, customer.Email, fmt.Sprintf("%d", customerResponse.ID))
		if err != nil {
			fmt.Printf("Error updating customer with external ID: %v\n", err)
			return fmt.Errorf("error updating customer with external ID: %v", err)
		}
	} else {
		customerResponse = &ecommerceInfra.EcommerceCustomerResponse{
			ID: func() int {
				id, _ := strconv.Atoi(customer.ExternalCustomerID)
				return id
			}(),
		}
		fmt.Printf("Using existing customer with ID: %d\n", customerResponse.ID)
	}

	if customer.BillingAddressID == "" {
		ecommerceBillingAddress := s.createEcommerceBillingAddressFromBilling(billing)

		fmt.Printf("Creando billing address en ecommerce para customer ID: %d\n", customerResponse.ID)

		billingAddressResponse, err = s.ecommerceSvc.CreateEcommerceBillingAddress(ctx, credentialsApiURL, credentialsApiKey, customerResponse.ID, ecommerceBillingAddress)
		if err != nil {
			fmt.Printf("Error creando billing address en ecommerce: %v\n", err)
			return fmt.Errorf("error creando billing address en ecommerce: %v", err)
		}

		fmt.Printf("Billing address creado exitosamente con ID: %d\n", billingAddressResponse.ID)

		err = s.customerService.UpdateBillingAddress(ctx, customer.Email, fmt.Sprintf("%d", billingAddressResponse.ID))
		if err != nil {
			fmt.Printf("Error updating customer with billing address ID: %v\n", err)
			return fmt.Errorf("error updating customer with billing address ID: %v", err)
		}
	} else {
		fmt.Printf("Using existing billing address with ID: %s\n", customer.BillingAddressID)
	}

	if customer.ShippingAddressID == "" {
		ecommerceShippingAddress := s.createEcommerceShippingAddressFromBilling(billing)

		fmt.Printf("Creando shipping address en ecommerce para customer ID: %d\n", customerResponse.ID)

		shippingAddressResponse, err := s.ecommerceSvc.CreateEcommerceShippingAddress(ctx, credentialsApiURL, credentialsApiKey, customerResponse.ID, ecommerceShippingAddress)
		if err != nil {
			fmt.Printf("Error creando shipping address en ecommerce: %v\n", err)
			return fmt.Errorf("error creando shipping address en ecommerce: %v", err)
		}

		fmt.Printf("Shipping address creado exitosamente con ID: %d\n", shippingAddressResponse.ID)

		err = s.customerService.UpdateShippingAddress(ctx, customer.Email, fmt.Sprintf("%d", shippingAddressResponse.ID))
		if err != nil {
			fmt.Printf("Error updating customer with shipping address ID: %v\n", err)
			return fmt.Errorf("error updating customer with shipping address ID: %v", err)
		}
	} else {
		fmt.Printf("Using existing shipping address with ID: %s\n", customer.ShippingAddressID)
	}

	ecommerceOrder := s.createEcommerceOrderFromOrders(orders, customerResponse.ID, item)

	fmt.Printf("Creando orden en ecommerce: %+v\n", ecommerceOrder)

	orderResponse, err := s.ecommerceSvc.CreateEcommerceOrder(ctx, credentialsApiURL, credentialsApiKey, ecommerceOrder)
	if err != nil {
		fmt.Printf("Error creando orden en ecommerce: %v\n", err)
		return fmt.Errorf("error creando orden en ecommerce: %v", err)
	}

	fmt.Printf("Orden creada exitosamente con ID: %d\n", orderResponse.ID)

	return nil
}
