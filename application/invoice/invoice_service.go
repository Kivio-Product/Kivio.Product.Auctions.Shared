package invoice

import (
	"context"
	"fmt"

	billingDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/billing"
	invoiceDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/invoice"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
	siigoClient "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/api/siigo"
)

type InvoiceService interface {
	CreateInvoiceForOrders(ctx context.Context, billingID string, orders []*orderDomain.Order, customer *billingDomain.Customer, invoiceConfig *billingDomain.InvoiceConfig, posName string) (*invoiceDomain.SiigoInvoiceResponse, error)
}

type invoiceService struct {
	siigoClient    siigoClient.SiigoClient
	invoiceFactory invoiceDomain.InvoiceFactory
}

func NewInvoiceService(siigoClient siigoClient.SiigoClient, invoiceFactory invoiceDomain.InvoiceFactory) InvoiceService {
	return &invoiceService{
		siigoClient:    siigoClient,
		invoiceFactory: invoiceFactory,
	}
}

func (s *invoiceService) CreateInvoiceForOrders(ctx context.Context, billingID string, orders []*orderDomain.Order, customer *billingDomain.Customer, invoiceConfig *billingDomain.InvoiceConfig, posName string) (*invoiceDomain.SiigoInvoiceResponse, error) {
	if len(orders) == 0 {
		return nil, fmt.Errorf("no orders provided for invoice creation")
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
		return nil, fmt.Errorf("error creating Siigo invoice: %w", err)
	}

	invoiceResponse, err := s.siigoClient.CreateInvoice(ctx, siigoInvoice)
	if err != nil {
		return nil, fmt.Errorf("error sending invoice to Siigo: %w", err)
	}

	fmt.Printf("Factura creada exitosamente en Siigo: ID=%s, Number=%d, Total=%.2f\n",
		invoiceResponse.ID, invoiceResponse.Number, invoiceResponse.Total)

	return invoiceResponse, nil
}
