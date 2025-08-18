package invoice

import "time"

type SiigoInvoice struct {
	ID           string             `json:"id,omitempty"`
	DocumentID   string             `json:"document_id"`
	Number       int                `json:"number,omitempty"`
	Name         string             `json:"name"`
	Date         string             `json:"date"`
	Customer     SiigoCustomer      `json:"customer"`
	CostCenter   int                `json:"cost_center,omitempty"`
	Currency     SiigoCurrency      `json:"currency"`
	Total        float64            `json:"total,omitempty"`
	Balance      float64            `json:"balance,omitempty"`
	Items        []SiigoInvoiceItem `json:"items"`
	Payments     []SiigoPayment     `json:"payments,omitempty"`
	Observations string             `json:"observations,omitempty"`
	Metadata     map[string]string  `json:"metadata,omitempty"`
}

type SiigoCustomer struct {
	Identification string `json:"identification"`
	BranchOffice   int    `json:"branch_office,omitempty"`
}

type SiigoCurrency struct {
	Code string `json:"code"`
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
	ID    int     `json:"id"`
	Value float64 `json:"value"`
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
	CustomerEmail   string
	CustomerID      string
	Orders          []*OrderInfo
	PointOfSaleID   string
	PointOfSaleName string
	TotalAmount     float64
	Currency        string
	BillingID       string
}

type OrderInfo struct {
	OrderID         string
	ItemName        string
	ItemDescription string
	Quantity        int
	UnitPrice       float64
	TotalPrice      float64
}
