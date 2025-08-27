package invoice

import "time"

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

type SiigoCurrency struct {
	Code         string  `json:"code"`
	ExchangeRate float64 `json:"exchange_rate,omitempty"`
}

type SiigoInvoiceItem struct {
	Code        string     `json:"code"`
	Description string     `json:"description"`
	Quantity    int        `json:"quantity"`
	Price       float64    `json:"price"`
	Discount    float64    `json:"discount,omitempty"`
	Taxes       []SiigoTax `json:"taxes,omitempty"`
}

type SiigoTax struct {
	ID int `json:"id"`
}

type SiigoPayment struct {
	ID      int     `json:"id"`
	Value   float64 `json:"value"`
	DueDate string  `json:"due_date,omitempty"`
}

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

type SiigoElectronicInvoice struct {
	Status       string `json:"status"`
	CUFE         string `json:"cufe,omitempty"`
	Number       string `json:"number,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

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

type OrderInfo struct {
	OrderID         string
	ItemName        string
	ItemDescription string
	Quantity        int
	UnitPrice       float64
	TotalPrice      float64
}

type SiigoDocument struct {
	ID int `json:"id"`
}

type SiigoAddress struct {
	Address    string    `json:"address"`
	City       SiigoCity `json:"city"`
	PostalCode string    `json:"postal_code,omitempty"`
}

type SiigoCity struct {
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	StateCode   string `json:"state_code"`
	StateName   string `json:"state_name"`
	CityCode    string `json:"city_code"`
	CityName    string `json:"city_name"`
}

type SiigoPhone struct {
	Indicative string `json:"indicative"`
	Number     string `json:"number"`
	Extension  string `json:"extension,omitempty"`
}

type SiigoContact struct {
	FirstName string     `json:"first_name"`
	LastName  string     `json:"last_name"`
	Email     string     `json:"email"`
	Phone     SiigoPhone `json:"phone,omitempty"`
}

type SiigoStamp struct {
	Send bool `json:"send"`
}

type SiigoMail struct {
	Send bool `json:"send"`
}

type SiigoTransport struct {
	FileNumber          int     `json:"file_number,omitempty"`
	ShipmentNumber      string  `json:"shipment_number,omitempty"`
	TransportedQuantity int     `json:"transported_quantity,omitempty"`
	MeasurementUnit     string  `json:"measurement_unit,omitempty"`
	FreightValue        float64 `json:"freight_value,omitempty"`
	PurchaseOrder       string  `json:"purchase_order,omitempty"`
	ServiceType         string  `json:"service_type,omitempty"`
}

type SiigoDiscount struct {
	ID         int     `json:"id"`
	Percentage float64 `json:"percentage,omitempty"`
	Value      float64 `json:"value,omitempty"`
}

// InvoiceRequest specific structures (simplified for user input)
type InvoiceAddress struct {
	Address    string
	City       InvoiceCity
	PostalCode string
}

type InvoiceCity struct {
	CountryCode string
	CountryName string
	StateCode   string
	StateName   string
	CityCode    string
	CityName    string
}

type InvoicePhone struct {
	Indicative string
	Number     string
	Extension  string
}

type InvoiceContact struct {
	FirstName string
	LastName  string
	Email     string
	Phone     InvoicePhone
}
