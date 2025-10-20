	package invoice

import (
	"fmt"
	"time"
)

// InvoiceFactory defines the contract for creating invoice instances
// 
// This interface provides methods for generating invoices in different formats,
// specifically for integration with external accounting systems like Siigo.
// The factory pattern ensures proper validation and transformation of invoice data.
type InvoiceFactory interface {
	// CreateSiigoInvoice creates a Siigo-formatted invoice from an invoice request
	//
	// This method transforms auction order data into a format compatible with Siigo's
	// accounting system, including customer information, order items, payments,
	// and tax calculations.
	//
	// Parameters:
	//   - request: The invoice request containing order and customer data
	//
	// Returns:
	//   - *SiigoInvoice: A properly formatted Siigo invoice
	//   - error: Validation or transformation errors
	//
	// Business Rules:
	//   - Customer email and billing ID are required
	//   - At least one order must be present
	//   - Tax ID is applied to all items
	//   - Currency defaults to COP if not specified
	//   - Payment due date is set to current date
	CreateSiigoInvoice(request *InvoiceRequest) (*SiigoInvoice, error)
}

// invoiceFactory is the concrete implementation of InvoiceFactory
// 
// This struct provides the default implementation for creating invoices,
// handling the transformation from auction order data to Siigo invoice format.
type invoiceFactory struct{}

// NewInvoiceFactory creates a new instance of InvoiceFactory
// 
// This constructor function returns a new invoice factory instance that can be used
// to create invoices in various formats. It follows the factory pattern to provide
// a clean interface for invoice creation.
//
// Returns:
//   - InvoiceFactory: A new invoice factory instance
func NewInvoiceFactory() InvoiceFactory {
	return &invoiceFactory{}
}

// CreateSiigoInvoice creates a Siigo-formatted invoice from an invoice request
// 
// This method performs comprehensive validation and transformation of auction order data
// into a format compatible with Siigo's accounting system. It handles customer information,
// order items, tax calculations, payment details, and metadata for proper invoice generation.
//
// Parameters:
//   - request: The invoice request containing order and customer data
//
// Returns:
//   - *SiigoInvoice: A properly formatted Siigo invoice ready for submission
//   - error: Validation errors if required fields are missing or invalid
//
// Side Effects:
//   - Generates invoice date using current timestamp
//   - Calculates total amount from order items
//   - Applies tax configuration to all items
//   - Sets payment due date to current date
//
// Business Rules:
//   - Invoice request cannot be nil
//   - Customer email and billing ID are mandatory
//   - At least one order must be present
//   - All items use the same tax ID from request
//   - Currency defaults to "COP" if not specified
//   - Item code is hardcoded to "1" (standard practice)
//   - Branch office is set to 0 (default)
//   - Payment due date matches invoice date
//
// Data Transformations:
//   - Converts InvoiceRequest orders to SiigoInvoiceItem format
//   - Transforms customer address to Siigo address structure
//   - Maps customer phones to Siigo phone format
//   - Converts customer contacts to Siigo contact format
//   - Adds metadata for tracking and audit purposes
func (f *invoiceFactory) CreateSiigoInvoice(request *InvoiceRequest) (*SiigoInvoice, error) {
	// Validate input parameters
	if request == nil {
		return nil, fmt.Errorf("invoice request cannot be nil")
	}

	if request.CustomerEmail == "" || request.BillingID == "" {
		return nil, fmt.Errorf("customer email and billing ID are required")
	}

	if len(request.Orders) == 0 {
		return nil, fmt.Errorf("at least one order is required")
	}

	// Process order items and calculate total
	var items []SiigoInvoiceItem
	var total float64

	for _, order := range request.Orders {
		item := SiigoInvoiceItem{
			Code:        "1",
			Description: order.ItemDescription,
			Quantity:    order.Quantity,
			Price:       order.UnitPrice,
			Discount:    0,
			Taxes: []SiigoTax{
				{
					ID: request.TaxID,
				},
			},
		}
		items = append(items, item)
		total += order.TotalPrice
	}

	// Transform customer address to Siigo format
	siigoAddress := SiigoAddress{
		Address: request.CustomerAddress.Address,
		City: SiigoCity{
			CountryCode: request.CustomerAddress.City.CountryCode,
			CountryName: request.CustomerAddress.City.CountryName,
			StateCode:   request.CustomerAddress.City.StateCode,
			StateName:   request.CustomerAddress.City.StateName,
			CityCode:    request.CustomerAddress.City.StateCode + request.CustomerAddress.City.CityCode,
			CityName:    request.CustomerAddress.City.CityName,
		},
		PostalCode: request.CustomerAddress.PostalCode,
	}

	// Transform customer phones to Siigo format
	var siigoPhones []SiigoPhone
	for _, phone := range request.CustomerPhones {
		siigoPhones = append(siigoPhones, SiigoPhone{
			Indicative: phone.Indicative,
			Number:     phone.Number,
			Extension:  phone.Extension,
		})
	}

	// Transform customer contacts to Siigo format
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

	// Create the complete Siigo invoice
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

	// Override currency if specified in request
	if request.Currency != "" {
		invoice.Currency.Code = request.Currency
	}

	return invoice, nil
}
