package invoice

import "time"

// SiigoInvoice represents a complete invoice structure for the Siigo accounting system
// 
// This struct contains all the necessary information to create an invoice in Siigo,
// including customer details, items, payments, taxes, and configuration options.
// It serves as the main data structure for invoice generation and processing.
type SiigoInvoice struct {
	Document         SiigoDocument          `json:"document"`
	Date             string                 `json:"date"`
	Customer         SiigoCustomer          `json:"customer"`
	CostCenter       int                    `json:"cost_center,omitempty"`
	Currency         SiigoCurrency          `json:"currency"`
	Seller           int                    `json:"seller,omitempty"`
	Stamp            SiigoStamp             `json:"stamp,omitempty"`
	Mail             SiigoMail              `json:"mail,omitempty"`
	Observations     string                 `json:"observations,omitempty"`
	Items            []SiigoInvoiceItem     `json:"items"`
	Payments         []SiigoPayment         `json:"payments,omitempty"`
	GlobalDiscounts  []SiigoDiscount        `json:"globaldiscounts,omitempty"`
	AdditionalFields map[string]interface{} `json:"additional_fields,omitempty"`
}

// SiigoCustomer represents customer information for Siigo invoice generation
// 
// This struct contains the customer details required by Siigo for invoice creation,
// including personal information, identification, and contact details.
type SiigoCustomer struct {
	PersonType     string         `json:"person_type"`
	IDType         string         `json:"id_type"`
	Identification string         `json:"identification"`
	BranchOffice   int            `json:"branch_office,omitempty"`
	Name           []string       `json:"name"`
	Address        SiigoAddress   `json:"address,omitempty"`
	Phones         []SiigoPhone   `json:"phones,omitempty"`
	Contacts       []SiigoContact `json:"contacts,omitempty"`
}

// SiigoCurrency represents currency information for Siigo invoices
// 
// This struct contains currency details including the currency code
// and optional exchange rate for multi-currency invoices.
type SiigoCurrency struct {
	Code         string  `json:"code"`
	ExchangeRate float64 `json:"exchange_rate,omitempty"`
}

// SiigoInvoiceItem represents an item or service on a Siigo invoice
// 
// This struct contains the details of individual items or services
// that appear on the invoice, including pricing, taxes, and discounts.
type SiigoInvoiceItem struct {
	Code        string     `json:"code"`
	Description string     `json:"description"`
	Quantity    int        `json:"quantity"`
	Price       float64    `json:"price"`
	Discount    float64    `json:"discount,omitempty"`
	Taxes       []SiigoTax `json:"taxes,omitempty"`
}

// SiigoTax represents tax information for Siigo invoice items
// 
// This struct contains the tax ID that applies to invoice items.
type SiigoTax struct {
	ID int `json:"id"`
}

// SiigoPayment represents payment information for Siigo invoices
// 
// This struct contains payment details including payment method ID,
// payment amount, and optional due date for payment terms.
type SiigoPayment struct {
	ID      int     `json:"id"`
	Value   float64 `json:"value"`
	DueDate string  `json:"due_date,omitempty"`
}

// SiigoInvoiceResponse represents the response from Siigo after invoice creation
// 
// This struct contains the invoice information returned by Siigo after
// successful invoice creation, including invoice ID, number, totals,
// and electronic invoice details.
type SiigoInvoiceResponse struct {
	ID                string                  `json:"id"`
	DocumentID        string                  `json:"document_id"`
	Number            int                     `json:"number"`
	Name              string                  `json:"name"`
	Date              string                  `json:"date"`
	Total             float64                 `json:"total"`
	Balance           float64                 `json:"balance"`
	Status            string                  `json:"status"`
	CreatedAt         time.Time               `json:"created"`
	UpdatedAt         time.Time               `json:"updated"`
	ElectronicInvoice *SiigoElectronicInvoice `json:"electronic_invoice,omitempty"`
}

// SiigoElectronicInvoice represents electronic invoice details from Siigo
// 
// This struct contains information about the electronic invoice processing,
// including status, CUFE (electronic invoice code), and error messages.
type SiigoElectronicInvoice struct {
	Status       string `json:"status"`
	CUFE         string `json:"cufe,omitempty"`
	Number       string `json:"number,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// InvoiceRequest represents the input data for creating an invoice
// 
// This struct contains all the necessary information from the auction system
// to generate an invoice, including customer details, order information,
// billing data, and configuration parameters for invoice generation.
type InvoiceRequest struct {
	DocumentID         int
	CustomerEmail      string
	CustomerID         string
	CustomerPersonType string
	CustomerIDType     string
	CustomerName       []string
	CustomerAddress    InvoiceAddress
	CustomerPhones     []InvoicePhone
	CustomerContacts   []InvoiceContact
	SellerID           int
	Orders             []*OrderInfo
	PaymentID          int
	TaxID              int
	PointOfSaleID      string
	PointOfSaleName    string
	TotalAmount        float64
	Currency           string
	BillingID          string
}

// OrderInfo represents order information for invoice generation
// 
// This struct contains details about individual orders that will be
// included in the invoice, including item information and pricing.
type OrderInfo struct {
	OrderID         string
	ItemName        string
	ItemDescription string
	Quantity        int
	UnitPrice       float64
	TotalPrice      float64
}

// SiigoDocument represents document type configuration for Siigo invoices
// 
// This struct contains the document type ID that determines the invoice format
// and processing rules in Siigo.
type SiigoDocument struct {
	ID int `json:"id"`
}

// SiigoAddress represents address information for Siigo customers
// 
// This struct contains address details including street address,
// city information, and optional postal code.
type SiigoAddress struct {
	Address    string    `json:"address"`
	City       SiigoCity `json:"city"`
	PostalCode string    `json:"postal_code,omitempty"`
}

// SiigoCity represents city information for Siigo addresses
// 
// This struct contains hierarchical location information including
// country, state, and city details with both codes and names.
type SiigoCity struct {
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	StateCode   string `json:"state_code"`
	StateName   string `json:"state_name"`
	CityCode    string `json:"city_code"`
	CityName    string `json:"city_name"`
}

// SiigoPhone represents phone number information for Siigo customers
// 
// This struct contains phone number details including country code,
// phone number, and optional extension.
type SiigoPhone struct {
	Indicative string `json:"indicative"`
	Number     string `json:"number"`
	Extension  string `json:"extension,omitempty"`
}

// SiigoContact represents contact information for Siigo customers
// 
// This struct contains contact person details including name,
// email, and optional phone information.
type SiigoContact struct {
	FirstName string     `json:"first_name"`
	LastName  string     `json:"last_name"`
	Email     string     `json:"email"`
	Phone     SiigoPhone `json:"phone,omitempty"`
}

// SiigoStamp represents stamp configuration for Siigo invoices
// 
// This struct controls whether the invoice should be stamped
// with official seals or certifications.
type SiigoStamp struct {
	Send bool `json:"send"`
}

// SiigoMail represents email configuration for Siigo invoices
// 
// This struct controls whether the invoice should be automatically
// sent via email to the customer.
type SiigoMail struct {
	Send bool `json:"send"`
}

// SiigoTransport represents transportation information for Siigo invoices
// 
// This struct contains shipping and transportation details for invoices
// that involve physical goods delivery.
type SiigoTransport struct {
	FileNumber          int     `json:"file_number,omitempty"`
	ShipmentNumber      string  `json:"shipment_number,omitempty"`
	TransportedQuantity int     `json:"transported_quantity,omitempty"`
	MeasurementUnit     string  `json:"measurement_unit,omitempty"`
	FreightValue        float64 `json:"freight_value,omitempty"`
	PurchaseOrder       string  `json:"purchase_order,omitempty"`
	ServiceType         string  `json:"service_type,omitempty"`
}

// SiigoDiscount represents discount information for Siigo invoices
// 
// This struct contains discount details that can be applied to invoices,
// supporting both percentage-based and fixed-value discounts.
type SiigoDiscount struct {
	ID         int     `json:"id"`
	Percentage float64 `json:"percentage,omitempty"`
	Value      float64 `json:"value,omitempty"`
}

// InvoiceAddress represents address information for invoice requests
// 
// This struct contains address details for customers in invoice generation,
// including street address, city information, and postal code.
type InvoiceAddress struct {
	Address    string
	City       InvoiceCity
	PostalCode string
}

// InvoiceCity represents city information for invoice addresses
// 
// This struct contains hierarchical location information for invoice
// addresses, including country, state, and city details.
type InvoiceCity struct {
	CountryCode string
	CountryName string
	StateCode   string
	StateName   string
	CityCode    string
	CityName    string
}

// InvoicePhone represents phone number information for invoice requests
// 
// This struct contains phone number details for customers in invoice
// generation, including country code, phone number, and extension.
type InvoicePhone struct {
	Indicative string
	Number     string
	Extension  string
}

// InvoiceContact represents contact information for invoice requests
// 
// This struct contains contact person details for customers in invoice
// generation, including name, email, and phone information.
type InvoiceContact struct {
	FirstName string
	LastName  string
	Email     string
	Phone     InvoicePhone
}
