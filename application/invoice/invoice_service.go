package invoice

import (
	"context"
	"fmt"

	invoiceDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/invoice"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
	siigoClient "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/api/siigo"
)

type InvoiceService interface {
	CreateInvoiceForOrders(ctx context.Context, billingID string, orders []*orderDomain.Order, posName string) (*invoiceDomain.SiigoInvoiceResponse, error)
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

func (s *invoiceService) CreateInvoiceForOrders(ctx context.Context, billingID string, orders []*orderDomain.Order, posName string) (*invoiceDomain.SiigoInvoiceResponse, error) {
	if len(orders) == 0 {
		return nil, fmt.Errorf("no orders provided for invoice creation")
	}

	firstOrder := orders[0]
	customerEmail := firstOrder.CustomerId
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

	invoiceRequest := &invoiceDomain.InvoiceRequest{
		CustomerEmail:   customerEmail,
		CustomerID:      customerEmail,
		Orders:          orderInfos,
		PointOfSaleID:   posID,
		PointOfSaleName: posName,
		TotalAmount:     totalAmount,
		Currency:        "COP",
		BillingID:       billingID,
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
