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
					ID: 1,
				},
			},
		}
		items = append(items, item)
		total += order.TotalPrice
	}

	siigoAddress := SiigoAddress{
		Address: request.CustomerAddress.Address,
		City: SiigoCity{
			CountryCode: request.CustomerAddress.City.CountryCode,
			CountryName: request.CustomerAddress.City.CountryName,
			StateCode:   request.CustomerAddress.City.StateCode,
			StateName:   request.CustomerAddress.City.StateName,
			CityCode:    request.CustomerAddress.City.CityCode,
			CityName:    request.CustomerAddress.City.CityName,
		},
		PostalCode: request.CustomerAddress.PostalCode,
	}

	var siigoPhones []SiigoPhone
	for _, phone := range request.CustomerPhones {
		siigoPhones = append(siigoPhones, SiigoPhone{
			Indicative: phone.Indicative,
			Number:     phone.Number,
			Extension:  phone.Extension,
		})
	}

	var siigoContacts []SiigoContact
	for _, contact := range request.CustomerContacts {
		siigoContacts = append(siigoContacts, SiigoContact{
			FirstName: contact.FirstName,
			LastName:  contact.LastName,
			Email:     contact.Email,
			Phone: SiigoPhone{
				Indicative: contact.Phone.Indicative,
				Number:     contact.Phone.Number,
				Extension:  contact.Phone.Extension,
			},
		})
	}

	invoice := &SiigoInvoice{
		Document: SiigoDocument{
			ID: request.DocumentID,
		},
		Date: time.Now().Format("2006-01-02"),
		Customer: SiigoCustomer{
			PersonType:     request.CustomerPersonType,
			IDType:         request.CustomerIDType,
			Identification: request.CustomerID,
			BranchOffice:   0,
			Name:           request.CustomerName,
			Address:        siigoAddress,
			Phones:         siigoPhones,
			Contacts:       siigoContacts,
		},
		Seller: request.SellerID,
		Currency: SiigoCurrency{
			Code: "COP",
		},
		Items: items,
		Payments: []SiigoPayment{
			{
				ID:      request.PaymentID,
				Value:   total,
				DueDate: time.Now().Format("2006-01-02"),
			},
		},
		Observations: fmt.Sprintf("Factura generada para punto de venta: %s - ID de facturación: %s",
			request.PointOfSaleName, request.BillingID),
		AdditionalFields: map[string]interface{}{
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
