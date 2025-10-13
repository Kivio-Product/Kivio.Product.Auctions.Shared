package invoice

import (
	"context"
	"fmt"
	"time"

	applicationLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/logging"
	customerService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/customer"
	ecommerceService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/ecommerce"
	billingDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/billing"
	invoiceDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/invoice"
	"github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/logging"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
	ecommerceInfra "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/ecommerce"
	infrastructureLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/logging"
	"strconv"
	"strings"
)

// EcommerceOrderStrategy implementa la estrategia de "facturación" creando ordenes en el ecommerce
// Se usa para items externos que vienen de un ecommerce integrado
type EcommerceOrderStrategy struct {
	ecommerceCredSvc ecommerceService.EcommerceCredentialsService
	ecommerceSvc     ecommerceService.EcommerceService
	customerService  customerService.CustomerService
	serviceLogger    *applicationLogging.ServiceLogger
	eventLogger      *logging.DomainEventLogger
}

// NewEcommerceOrderStrategy crea una nueva instancia del strategy para ordenes de ecommerce
func NewEcommerceOrderStrategy(
	ecommerceCredSvc ecommerceService.EcommerceCredentialsService,
	ecommerceSvc ecommerceService.EcommerceService,
	customerService customerService.CustomerService,
) *EcommerceOrderStrategy {
	loggerRepo := infrastructureLogging.GetLoggerRepository()
	serviceLogger := applicationLogging.NewServiceLogger(loggerRepo, "EcommerceOrderStrategy")
	eventLogger := logging.NewDomainEventLogger(loggerRepo.GetLogger())

	return &EcommerceOrderStrategy{
		ecommerceCredSvc: ecommerceCredSvc,
		ecommerceSvc:     ecommerceSvc,
		customerService:  customerService,
		serviceLogger:    serviceLogger,
		eventLogger:      eventLogger,
	}
}

// CreateInvoiceForOrders crea ordenes en el ecommerce para items externos
// En lugar de crear una factura en Siigo, crea una orden en el sistema de ecommerce
func (s *EcommerceOrderStrategy) CreateInvoiceForOrders(
	ctx context.Context,
	billingID string,
	orders []*orderDomain.Order,
	customer *billingDomain.Customer,
	invoiceConfig *billingDomain.InvoiceConfig,
	posName string,
) (*invoiceDomain.SiigoInvoiceResponse, error) {
	start := time.Now()

	s.serviceLogger.LogServiceStart(ctx, "CreateInvoiceForOrders", map[string]interface{}{
		"strategy":    "ecommerce_order",
		"billing_id":  billingID,
		"order_count": len(orders),
		"pos_name":    posName,
	})

	if len(orders) == 0 {
		err := fmt.Errorf("no orders provided for ecommerce order creation")
		s.serviceLogger.LogServiceError(ctx, "CreateInvoiceForOrders", err, map[string]interface{}{
			"billing_id": billingID,
			"error":      "no_orders_provided",
		})
		return nil, err
	}

	firstOrder := orders[0]
	posID := firstOrder.PointOfSaleId

	// Obtener credenciales del ecommerce
	credentials, err := s.ecommerceCredSvc.GetCredentials(ctx, posID)
	if err != nil {
		s.serviceLogger.LogServiceError(ctx, "CreateInvoiceForOrders", err, map[string]interface{}{
			"billing_id": billingID,
			"pos_id":     posID,
			"error":      "failed_to_get_credentials",
		})
		return nil, fmt.Errorf("error getting ecommerce credentials: %w", err)
	}

	// Crear billing mock con customer info
	billing := &billingDomain.Billing{
		Customer: customer,
	}

	// Crear orden en ecommerce
	// Nota: Esta lógica está simplificada. La lógica completa de createEcommerceCustomerAndOrder
	// debería ser extraída a un método helper o service separado
	err = s.createEcommerceOrder(ctx, credentials.ApiURL, credentials.ApiKey, billing, orders, posID)
	if err != nil {
		s.serviceLogger.LogServiceError(ctx, "CreateInvoiceForOrders", err, map[string]interface{}{
			"billing_id": billingID,
			"pos_id":     posID,
			"error":      "failed_to_create_ecommerce_order",
		})
		return nil, fmt.Errorf("error creating ecommerce order: %w", err)
	}

	s.serviceLogger.LogServiceEnd(ctx, "CreateInvoiceForOrders", time.Since(start), map[string]interface{}{
		"billing_id":  billingID,
		"order_count": len(orders),
		"success":     true,
	})

	// Retornar respuesta mock ya que la interfaz espera SiigoInvoiceResponse
	// En el futuro esto debería ser una respuesta genérica
	return &invoiceDomain.SiigoInvoiceResponse{
		ID:     billingID, // Usar billingID como referencia
		Number: 0,         // No hay número de factura en ecommerce
		Total:  0,         // Calcular total si es necesario
	}, nil
}

// createEcommerceOrder crea una orden completa en el ecommerce
func (s *EcommerceOrderStrategy) createEcommerceOrder(
	ctx context.Context,
	apiURL string,
	apiKey string,
	billing *billingDomain.Billing,
	orders []*orderDomain.Order,
	posID string,
) error {
	fmt.Printf("[EcommerceOrderStrategy] Starting createEcommerceOrder for %d orders\n", len(orders))

	// 1. Obtener o crear customer
	customer, err := s.customerService.GetOrCreateCustomer(ctx, billing.Customer.Email)
	if err != nil {
		return fmt.Errorf("error getting or creating customer: %w", err)
	}

	var customerResponse *ecommerceInfra.EcommerceCustomerResponse

	// 2. Crear customer en ecommerce si no existe
	if customer.ExternalCustomerID == "" {
		ecommerceCustomer := s.createEcommerceCustomer(billing)
		customerResponse, err = s.ecommerceSvc.CreateEcommerceCustomer(ctx, apiURL, apiKey, ecommerceCustomer)
		if err != nil {
			return fmt.Errorf("error creating customer in ecommerce: %w", err)
		}

		err = s.customerService.UpdateExternalCustomerID(ctx, customer.Email, fmt.Sprintf("%d", customerResponse.ID))
		if err != nil {
			return fmt.Errorf("error updating customer with external ID: %w", err)
		}
	} else {
		customerResponse = &ecommerceInfra.EcommerceCustomerResponse{
			ID: func() int {
				id, _ := strconv.Atoi(customer.ExternalCustomerID)
				return id
			}(),
		}
	}

	// 3. Crear billing address si no existe
	var billingAddressID int
	if customer.BillingAddressID == "" {
		billingAddress := s.createBillingAddress(billing)
		billingAddressResponse, err := s.ecommerceSvc.CreateEcommerceBillingAddress(ctx, apiURL, apiKey, customerResponse.ID, billingAddress)
		if err != nil {
			return fmt.Errorf("error creating billing address: %w", err)
		}
		billingAddressID = billingAddressResponse.ID

		err = s.customerService.UpdateBillingAddress(ctx, customer.Email, fmt.Sprintf("%d", billingAddressID))
		if err != nil {
			return fmt.Errorf("error updating billing address ID: %w", err)
		}
	} else {
		billingAddressID, _ = strconv.Atoi(customer.BillingAddressID)
	}

	// 4. Crear shipping address si no existe
	var shippingAddressID int
	if customer.ShippingAddressID == "" {
		shippingAddress := s.createShippingAddress(billing)
		shippingAddressResponse, err := s.ecommerceSvc.CreateEcommerceShippingAddress(ctx, apiURL, apiKey, customerResponse.ID, shippingAddress)
		if err != nil {
			return fmt.Errorf("error creating shipping address: %w", err)
		}
		shippingAddressID = shippingAddressResponse.ID

		err = s.customerService.UpdateShippingAddress(ctx, customer.Email, fmt.Sprintf("%d", shippingAddressID))
		if err != nil {
			return fmt.Errorf("error updating shipping address ID: %w", err)
		}
	} else {
		shippingAddressID, _ = strconv.Atoi(customer.ShippingAddressID)
	}

	// 5. Crear orden simple en ecommerce
	totalAmount := float64(0)
	for _, order := range orders {
		totalAmount += float64(order.OfferedAmount) / 100.0
	}

	ecommerceOrder := s.createSimpleOrder(orders, customerResponse.ID, billingAddressID, shippingAddressID, totalAmount)
	orderResponse, err := s.ecommerceSvc.CreateEcommerceSimpleOrder(ctx, apiURL, apiKey, ecommerceOrder)
	if err != nil {
		return fmt.Errorf("error creating order in ecommerce: %w", err)
	}

	fmt.Printf("[EcommerceOrderStrategy] Order created successfully with ID: %d\n", orderResponse.ID)
	return nil
}

// Helper methods para crear estructuras de ecommerce
func (s *EcommerceOrderStrategy) createEcommerceCustomer(billing *billingDomain.Billing) *ecommerceInfra.EcommerceCustomer {
	now := time.Now()
	customer := &ecommerceInfra.EcommerceCustomer{
		Email:        billing.Customer.Email,
		Active:       true,
		CreatedOnUTC: now,
		RoleIDs:      []int{4},
	}

	if len(billing.Customer.Name) > 0 {
		if len(billing.Customer.Name) > 1 {
			customer.FirstName = billing.Customer.Name[0]
			customer.LastName = strings.Join(billing.Customer.Name[1:], " ")
		} else {
			nameParts := strings.Fields(billing.Customer.Name[0])
			if len(nameParts) > 1 {
				customer.FirstName = nameParts[0]
				customer.LastName = strings.Join(nameParts[1:], " ")
			} else {
				customer.FirstName = billing.Customer.Name[0]
			}
		}
	}

	return customer
}

func (s *EcommerceOrderStrategy) createBillingAddress(billing *billingDomain.Billing) *ecommerceInfra.EcommerceAddress {
	now := time.Now()
	firstName, lastName := s.splitCustomerName(billing.Customer.Name)

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
		CountryID:     49,
	}

	if len(billing.Customer.Phones) > 0 {
		address.PhoneNumber = billing.Customer.Phones[0].Indicative + billing.Customer.Phones[0].Number
	}

	return address
}

func (s *EcommerceOrderStrategy) createShippingAddress(billing *billingDomain.Billing) *ecommerceInfra.EcommerceAddress {
	now := time.Now()
	firstName, lastName := s.splitCustomerName(billing.Customer.Name)

	var addressInfo billingDomain.CustomerAddress
	if billing.Customer.ShippingAddress != nil {
		addressInfo = *billing.Customer.ShippingAddress
	} else {
		addressInfo = billing.Customer.Address
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
		CountryID:     49,
	}

	if len(billing.Customer.Phones) > 0 {
		address.PhoneNumber = billing.Customer.Phones[0].Indicative + billing.Customer.Phones[0].Number
	}

	return address
}

func (s *EcommerceOrderStrategy) createSimpleOrder(
	orders []*orderDomain.Order,
	customerID int,
	billingAddressID int,
	shippingAddressID int,
	totalAmount float64,
) *ecommerceInfra.EcommerceSimpleOrder {
	now := time.Now()

	return &ecommerceInfra.EcommerceSimpleOrder{
		StoreID:                 1,
		PaymentMethodSystemName: "Payments.CashOnDelivery",
		CustomerCurrencyCode:    "COP",
		CurrencyRate:            1,
		OrderTax:                0,
		OrderTotal:              totalAmount,
		PaidDateUTC:             now,
		CreatedOnUTC:            now,
		CustomerID:              customerID,
		BillingAddress:          &ecommerceInfra.EcommerceSimpleAddress{ID: billingAddressID},
		ShippingAddress:         &ecommerceInfra.EcommerceSimpleAddress{ID: shippingAddressID},
	}
}

func (s *EcommerceOrderStrategy) splitCustomerName(names []string) (string, string) {
	if len(names) == 0 {
		return "", ""
	}

	if len(names) > 1 {
		return names[0], strings.Join(names[1:], " ")
	}

	nameParts := strings.Fields(names[0])
	if len(nameParts) > 1 {
		return nameParts[0], strings.Join(nameParts[1:], " ")
	}

	return names[0], ""
}

// GetInvoiceType retorna el tipo de facturación
func (s *EcommerceOrderStrategy) GetInvoiceType() string {
	return "ecommerce_order"
}
