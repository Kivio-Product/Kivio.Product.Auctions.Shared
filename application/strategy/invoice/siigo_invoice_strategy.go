package invoice

import (
	"context"
	"fmt"
	"time"

	applicationLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/logging"
	billingDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/billing"
	invoiceDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/invoice"
	"github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/logging"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
	siigoClient "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/api/siigo"
	infrastructureLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/logging"
)

type SiigoInvoiceStrategy struct {
	siigoClient    siigoClient.SiigoClient
	invoiceFactory invoiceDomain.InvoiceFactory
	serviceLogger  *applicationLogging.ServiceLogger
	eventLogger    *logging.DomainEventLogger
}

func NewSiigoInvoiceStrategy(
	siigoClient siigoClient.SiigoClient,
	invoiceFactory invoiceDomain.InvoiceFactory,
) *SiigoInvoiceStrategy {
	loggerRepo := infrastructureLogging.GetLoggerRepository()
	serviceLogger := applicationLogging.NewServiceLogger(loggerRepo, "SiigoInvoiceStrategy")
	eventLogger := logging.NewDomainEventLogger(loggerRepo.GetLogger())

	return &SiigoInvoiceStrategy{
		siigoClient:    siigoClient,
		invoiceFactory: invoiceFactory,
		serviceLogger:  serviceLogger,
		eventLogger:    eventLogger,
	}
}

func (s *SiigoInvoiceStrategy) CreateInvoiceForOrders(
	ctx context.Context,
	billingID string,
	orders []*orderDomain.Order,
	customer *billingDomain.Customer,
	invoiceConfig *billingDomain.InvoiceConfig,
	posName string,
) (*invoiceDomain.SiigoInvoiceResponse, error) {
	start := time.Now()

	orderIds := make([]string, len(orders))
	var totalAmountSum float64
	for i, order := range orders {
		orderIds[i] = order.OrderId
		totalAmountSum += float64(order.OfferedAmount)
	}

	s.serviceLogger.LogServiceStart(ctx, "CreateInvoiceForOrders", map[string]interface{}{
		"strategy":      "siigo",
		"billing_id":    billingID,
		"order_count":   len(orders),
		"order_ids":     orderIds,
		"customer_id":   customer.Identification,
		"customer_name": customer.Name,
		"pos_name":      posName,
		"total_amount":  totalAmountSum,
	})

	if len(orders) == 0 {
		err := fmt.Errorf("no orders provided for invoice creation")
		s.serviceLogger.LogServiceError(ctx, "CreateInvoiceForOrders", err, map[string]interface{}{
			"billing_id": billingID,
			"error":      "no_orders_provided",
		})
		return nil, err
	}

	firstOrder := orders[0]
	posID := firstOrder.PointOfSaleId

	var orderInfos []*invoiceDomain.OrderInfo
	var totalAmount float64

	for _, order := range orders {
		itemName := order.ExtraData
		if itemName == "" {
			itemName = fmt.Sprintf("Producto Order ID: %s", order.OrderId)
		}

		orderInfo := &invoiceDomain.OrderInfo{
			OrderID:         order.OrderId,
			ItemName:        itemName,
			ItemDescription: fmt.Sprintf("Orden de subasta - %s", itemName),
			Quantity:        order.TotalQuantity,
			UnitPrice:       float64(order.OfferedAmount) / float64(order.TotalQuantity),
			TotalPrice:      float64(order.OfferedAmount),
		}

		orderInfos = append(orderInfos, orderInfo)
		totalAmount += float64(order.OfferedAmount)
	}

	invoiceAddress := invoiceDomain.InvoiceAddress{
		Address: customer.Address.Address,
		City: invoiceDomain.InvoiceCity{
			CountryCode: customer.Address.City.CountryCode,
			CountryName: customer.Address.City.CountryName,
			StateCode:   customer.Address.City.StateCode,
			StateName:   customer.Address.City.StateName,
			CityCode:    customer.Address.City.CityCode,
			CityName:    customer.Address.City.CityName,
		},
		PostalCode: customer.Address.PostalCode,
	}

	var invoicePhones []invoiceDomain.InvoicePhone
	for _, phone := range customer.Phones {
		invoicePhones = append(invoicePhones, invoiceDomain.InvoicePhone{
			Indicative: phone.Indicative,
			Number:     phone.Number,
			Extension:  phone.Extension,
		})
	}

	var invoiceContacts []invoiceDomain.InvoiceContact
	for _, contact := range customer.Contacts {
		invoiceContacts = append(invoiceContacts, invoiceDomain.InvoiceContact{
			FirstName: contact.FirstName,
			LastName:  contact.LastName,
			Email:     contact.Email,
			Phone: invoiceDomain.InvoicePhone{
				Indicative: contact.Phone.Indicative,
				Number:     contact.Phone.Number,
				Extension:  contact.Phone.Extension,
			},
		})
	}

	invoiceRequest := &invoiceDomain.InvoiceRequest{
		DocumentID:         invoiceConfig.DocumentID,
		CustomerEmail:      customer.Email,
		CustomerID:         customer.Identification,
		CustomerPersonType: customer.PersonType,
		CustomerIDType:     customer.IDType,
		CustomerName:       customer.Name,
		CustomerAddress:    invoiceAddress,
		CustomerPhones:     invoicePhones,
		CustomerContacts:   invoiceContacts,
		SellerID:           invoiceConfig.SellerID,
		Orders:             orderInfos,
		PaymentID:          invoiceConfig.PaymentID,
		TaxID:              invoiceConfig.TaxID,
		PointOfSaleID:      posID,
		PointOfSaleName:    posName,
		TotalAmount:        totalAmount,
		Currency:           "COP",
		BillingID:          billingID,
	}

	siigoInvoice, err := s.invoiceFactory.CreateSiigoInvoice(invoiceRequest)
	if err != nil {
		s.serviceLogger.LogServiceError(ctx, "CreateInvoiceForOrders", err, map[string]interface{}{
			"billing_id":  billingID,
			"customer_id": customer.Identification,
			"order_count": len(orders),
			"error":       "failed_to_create_siigo_invoice",
		})
		return nil, fmt.Errorf("error creating Siigo invoice: %w", err)
	}

	s.serviceLogger.LogExternalAPICall(ctx, "Siigo", "/invoices", 0, false, map[string]interface{}{
		"operation":    "create_invoice",
		"billing_id":   billingID,
		"customer_id":  customer.Identification,
		"total_amount": totalAmount,
		"order_count":  len(orders),
	})

	invoiceResponse, err := s.siigoClient.CreateInvoice(ctx, siigoInvoice)
	if err != nil {
		s.serviceLogger.LogServiceError(ctx, "CreateInvoiceForOrders", err, map[string]interface{}{
			"billing_id":   billingID,
			"customer_id":  customer.Identification,
			"total_amount": totalAmount,
			"error":        "failed_to_send_invoice_to_siigo",
		})
		return nil, fmt.Errorf("error sending invoice to Siigo: %w", err)
	}

	s.serviceLogger.LogWorkflow(ctx, "InvoiceGeneration", "InvoiceCreated", map[string]interface{}{
		"strategy":       "siigo",
		"invoice_id":     invoiceResponse.ID,
		"invoice_number": invoiceResponse.Number,
		"billing_id":     billingID,
		"customer_id":    customer.Identification,
		"total_amount":   invoiceResponse.Total,
		"order_count":    len(orders),
		"pos_id":         posID,
	})

	s.serviceLogger.LogServiceEnd(ctx, "CreateInvoiceForOrders", time.Since(start), map[string]interface{}{
		"billing_id":     billingID,
		"invoice_id":     invoiceResponse.ID,
		"invoice_number": invoiceResponse.Number,
		"customer_id":    customer.Identification,
		"total_amount":   invoiceResponse.Total,
		"order_count":    len(orders),
		"success":        true,
	})

	fmt.Printf("[SiigoInvoiceStrategy] Factura creada exitosamente en Siigo: ID=%s, Number=%d, Total=%.2f\n",
		invoiceResponse.ID, invoiceResponse.Number, invoiceResponse.Total)

	return invoiceResponse, nil
}

func (s *SiigoInvoiceStrategy) GetInvoiceType() string {
	return "siigo"
}
