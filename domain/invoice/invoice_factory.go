package invoice

import (
	"fmt"
	"time"
)

type InvoiceFactory interface {
	CreateSiigoInvoice(request *InvoiceRequest) (*SiigoInvoice, error)
}

type invoiceFactory struct{}

func NewInvoiceFactory() InvoiceFactory {
	return &invoiceFactory{}
}

func (f *invoiceFactory) CreateSiigoInvoice(request *InvoiceRequest) (*SiigoInvoice, error) {
	if request == nil {
		return nil, fmt.Errorf("invoice request cannot be nil")
	}

	if request.CustomerEmail == "" || request.BillingID == "" {
		return nil, fmt.Errorf("customer email and billing ID are required")
	}

	if len(request.Orders) == 0 {
		return nil, fmt.Errorf("at least one order is required")
	}

	var items []SiigoInvoiceItem
	var total float64

	for _, order := range request.Orders {
		item := SiigoInvoiceItem{
			Code:        order.OrderID,
			Description: order.ItemDescription,
			Quantity:    order.Quantity,
			Price:       order.UnitPrice,
			Discount:    0,
			Taxes: []SiigoTax{
				{
					ID:    1,
					Value: 19,
				},
			},
		}
		items = append(items, item)
		total += order.TotalPrice
	}

	invoice := &SiigoInvoice{
		DocumentID: "1",
		Name:       fmt.Sprintf("Factura Kivio - %s", request.BillingID),
		Date:       time.Now().Format("2006-01-02"),
		Customer: SiigoCustomer{
			Identification: request.CustomerEmail,
			BranchOffice:   0,
		},
		Currency: SiigoCurrency{
			Code: "COP",
		},
		Items: items,
		Payments: []SiigoPayment{
			{
				ID:      1,
				Value:   total,
				DueDate: time.Now().Format("2006-01-02"),
			},
		},
		Observations: fmt.Sprintf("Factura generada para punto de venta: %s - ID de facturación: %s",
			request.PointOfSaleName, request.BillingID),
		Metadata: map[string]string{
			"billing_id":     request.BillingID,
			"pos_id":         request.PointOfSaleID,
			"customer_email": request.CustomerEmail,
			"generated_by":   "kivio_auctions",
		},
	}

	if request.Currency != "" {
		invoice.Currency.Code = request.Currency
	}

	return invoice, nil
}
