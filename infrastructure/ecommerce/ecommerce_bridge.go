package ecommerce

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	customerDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/customer"
	itemDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"

	ecommerceClient "github.com/Kivio-Product/Kivio.Product.Auctions.EcommerceClient"
)

type EcommerceAddress struct {
	FirstName       string    `json:"first_name"`
	LastName        string    `json:"last_name"`
	Email           string    `json:"email"`
	Company         string    `json:"company"`
	CountryID       int       `json:"country_id"`
	Country         string    `json:"country"`
	StateProvinceID int       `json:"state_province_id"`
	City            string    `json:"city"`
	Address1        string    `json:"address1"`
	Address2        string    `json:"address2"`
	ZipPostalCode   string    `json:"zip_postal_code"`
	PhoneNumber     string    `json:"phone_number"`
	FaxNumber       string    `json:"fax_number"`
	CustomerAttrs   string    `json:"customer_attributes"`
	CreatedOnUTC    time.Time `json:"created_on_utc"`
	Province        string    `json:"province"`
	ID              int       `json:"id"`
}

type EcommerceCustomer struct {
	BillingAddress         *EcommerceAddress  `json:"billing_address"`
	ShippingAddress        *EcommerceAddress  `json:"shipping_address"`
	Addresses              []EcommerceAddress `json:"addresses"`
	CustomerGUID           string             `json:"customer_guid"`
	Username               string             `json:"username"`
	Email                  string             `json:"email"`
	FirstName              string             `json:"first_name"`
	LastName               string             `json:"last_name"`
	LanguageID             int                `json:"language_id"`
	CurrencyID             int                `json:"currency_id"`
	DateOfBirth            *time.Time         `json:"date_of_birth"`
	Gender                 string             `json:"gender"`
	AdminComment           string             `json:"admin_comment"`
	IsTaxExempt            bool               `json:"is_tax_exempt"`
	HasShoppingCartItems   bool               `json:"has_shopping_cart_items"`
	Active                 bool               `json:"active"`
	Deleted                bool               `json:"deleted"`
	IsSystemAccount        bool               `json:"is_system_account"`
	SystemName             string             `json:"system_name"`
	LastIPAddress          string             `json:"last_ip_address"`
	CreatedOnUTC           time.Time          `json:"created_on_utc"`
	LastLoginDateUTC       *time.Time         `json:"last_login_date_utc"`
	LastActivityDateUTC    *time.Time         `json:"last_activity_date_utc"`
	RegisteredInStoreID    int                `json:"registered_in_store_id"`
	SubscribedToNewsletter bool               `json:"subscribed_to_newsletter"`
	VatNumber              string             `json:"vat_number"`
	VatNumberStatusID      int                `json:"vat_number_status_id"`
	EuCookieLawAccepted    bool               `json:"eu_cookie_law_accepted"`
	Company                string             `json:"company"`
	RoleIDs                []int              `json:"role_ids"`
	ID                     int                `json:"id"`
}

type EcommerceCustomerRequest struct {
	Customers []EcommerceCustomer `json:"customers"`
}

type EcommerceCustomerResponse struct {
	ID      int    `json:"id"`
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type EcommerceProductAttribute struct {
	Value string `json:"value"`
	ID    int    `json:"id"`
}

type EcommerceOrderItem struct {
	ProductAttributes     []EcommerceProductAttribute `json:"product_attributes"`
	Quantity              int                         `json:"quantity"`
	UnitPriceInclTax      float64                     `json:"unit_price_incl_tax"`
	UnitPriceExclTax      float64                     `json:"unit_price_excl_tax"`
	PriceInclTax          float64                     `json:"price_incl_tax"`
	PriceExclTax          float64                     `json:"price_excl_tax"`
	DiscountAmountInclTax float64                     `json:"discount_amount_incl_tax"`
	DiscountAmountExclTax float64                     `json:"discount_amount_excl_tax"`
	OriginalProductCost   float64                     `json:"original_product_cost"`
	AttributeDescription  string                      `json:"attribute_description"`
	DownloadCount         int                         `json:"download_count"`
	IsDownloadActivated   bool                        `json:"isDownload_activated"`
	LicenseDownloadID     int                         `json:"license_download_id"`
	ItemWeight            float64                     `json:"item_weight"`
	RentalStartDateUTC    *time.Time                  `json:"rental_start_date_utc"`
	RentalEndDateUTC      *time.Time                  `json:"rental_end_date_utc"`
}

type EcommerceOrder struct {
	StoreID                                 int                  `json:"store_id"`
	PickUpInStore                           bool                 `json:"pick_up_in_store"`
	PaymentMethodSystemName                 string               `json:"payment_method_system_name"`
	CustomerCurrencyCode                    string               `json:"customer_currency_code"`
	CurrencyRate                            float64              `json:"currency_rate"`
	CustomerTaxDisplayTypeID                int                  `json:"customer_tax_display_type_id"`
	VatNumber                               string               `json:"vat_number"`
	OrderSubtotalInclTax                    float64              `json:"order_subtotal_incl_tax"`
	OrderSubtotalExclTax                    float64              `json:"order_subtotal_excl_tax"`
	OrderSubTotalDiscountInclTax            float64              `json:"order_sub_total_discount_incl_tax"`
	OrderSubTotalDiscountExclTax            float64              `json:"order_sub_total_discount_excl_tax"`
	OrderShippingInclTax                    float64              `json:"order_shipping_incl_tax"`
	OrderShippingExclTax                    float64              `json:"order_shipping_excl_tax"`
	PaymentMethodAdditionalFeeInclTax       float64              `json:"payment_method_additional_fee_incl_tax"`
	PaymentMethodAdditionalFeeExclTax       float64              `json:"payment_method_additional_fee_excl_tax"`
	TaxRates                                string               `json:"tax_rates"`
	OrderTax                                float64              `json:"order_tax"`
	OrderDiscount                           float64              `json:"order_discount"`
	OrderTotal                              float64              `json:"order_total"`
	RefundedAmount                          float64              `json:"refunded_amount"`
	RewardPointsWereAdded                   bool                 `json:"reward_points_were_added"`
	CheckoutAttributeDescription            string               `json:"checkout_attribute_description"`
	CustomerLanguageID                      int                  `json:"customer_language_id"`
	AffiliateID                             int                  `json:"affiliate_id"`
	CustomerIP                              string               `json:"customer_ip"`
	AuthorizationTransactionID              string               `json:"authorization_transaction_id"`
	AuthorizationTransactionCode            string               `json:"authorization_transaction_code"`
	AuthorizationTransactionResult          string               `json:"authorization_transaction_result"`
	CaptureTransactionID                    string               `json:"capture_transaction_id"`
	CaptureTransactionResult                string               `json:"capture_transaction_result"`
	SubscriptionTransactionID               string               `json:"subscription_transaction_id"`
	PaidDateUTC                             *time.Time           `json:"paid_date_utc"`
	ShippingMethod                          string               `json:"shipping_method"`
	ShippingRateComputationMethodSystemName string               `json:"shipping_rate_computation_method_system_name"`
	CustomValuesXml                         string               `json:"custom_values_xml"`
	Deleted                                 bool                 `json:"deleted"`
	CreatedOnUTC                            time.Time            `json:"created_on_utc"`
	CustomerID                              int                  `json:"customer_id"`
	BillingAddress                          *EcommerceAddress    `json:"billing_address"`
	ShippingAddress                         *EcommerceAddress    `json:"shipping_address"`
	OrderItems                              []EcommerceOrderItem `json:"order_items"`
}

type EcommerceOrderRequest struct {
	Order EcommerceOrder `json:"order"`
}

type EcommerceOrderResponse struct {
	ID      int    `json:"id"`
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type EcommerceBridge struct {
	client ecommerceClient.EcommerceService
}

func NewEcommerceBridge() *EcommerceBridge {
	return &EcommerceBridge{
		client: ecommerceClient.NewEcommerceService(),
	}
}

type EcommerceService interface {
	GetItems(ctx context.Context, apiUrl, apiKey string, page, limit int) ([]itemDomain.Item, error)
	GetItemsRaw(ctx context.Context, apiUrl, apiKey string, page, limit int, publishedStatus bool) ([]byte, error)
	GetItemByID(ctx context.Context, id, apiUrl, apiKey string) (*itemDomain.Item, error)
	GetItemByIDRaw(ctx context.Context, id, apiUrl, apiKey string) ([]byte, error)
	GetCustomers(ctx context.Context, apiUrl, apiKey string) ([]customerDomain.Customer, error)
	GetCustomerByID(ctx context.Context, id, apiUrl, apiKey string) (*customerDomain.Customer, error)
	GetApiKey(ctx context.Context, username, password, tokenUrl string) (string, error)
	UpdateItemStock(ctx context.Context, apiUrl, apiKey, itemId string, newStock int) error
	GetAllItemsRaw(ctx context.Context, apiUrl, apiKey string) ([]byte, error)
	CreateEcommerceCustomer(ctx context.Context, apiUrl, apiKey string, customer *EcommerceCustomer) (*EcommerceCustomerResponse, error)
	CreateEcommerceOrder(ctx context.Context, apiUrl, apiKey string, order *EcommerceOrder) (*EcommerceOrderResponse, error)
}

func (b *EcommerceBridge) GetItems(ctx context.Context, apiUrl, apiKey string, page, limit int) ([]itemDomain.Item, error) {
	items, err := b.client.GetItems(ctx, apiUrl, apiKey, page, limit)
	if err != nil {
		return nil, err
	}

	result := make([]itemDomain.Item, len(items))
	for i, item := range items {
		result[i] = itemDomain.Item{
			ItemId:        item.ItemId,
			Name:          item.Name,
			Description:   item.Description,
			ExternalId:    item.ExternalId,
			PointOfSaleId: item.PointOfSaleId,
			Url:           item.Url,
			Source:        item.Source,
		}
	}
	return result, nil
}

func (b *EcommerceBridge) GetItemsRaw(ctx context.Context, apiUrl, apiKey string, page, limit int, publishedStatus bool) ([]byte, error) {
	return b.client.GetItemsRaw(ctx, apiUrl, apiKey, page, limit, publishedStatus)
}

func (b *EcommerceBridge) GetItemByID(ctx context.Context, id, apiUrl, apiKey string) (*itemDomain.Item, error) {
	item, err := b.client.GetItemByID(ctx, id, apiUrl, apiKey)
	if err != nil {
		return nil, err
	}

	return &itemDomain.Item{
		ItemId:        item.ItemId,
		Name:          item.Name,
		Description:   item.Description,
		ExternalId:    item.ExternalId,
		PointOfSaleId: item.PointOfSaleId,
		Url:           item.Url,
		Source:        item.Source,
	}, nil
}

func (b *EcommerceBridge) GetItemByIDRaw(ctx context.Context, id, apiUrl, apiKey string) ([]byte, error) {
	return b.client.GetItemByIDRaw(ctx, id, apiUrl, apiKey)
}

func (b *EcommerceBridge) GetCustomers(ctx context.Context, apiUrl, apiKey string) ([]customerDomain.Customer, error) {
	// TODO: Implement customer mapping when needed
	return nil, fmt.Errorf("GetCustomers not implemented - customer domain structure changed")
}

func (b *EcommerceBridge) GetCustomerByID(ctx context.Context, id, apiUrl, apiKey string) (*customerDomain.Customer, error) {
	// TODO: Implement customer mapping when needed
	return nil, fmt.Errorf("GetCustomerByID not implemented - customer domain structure changed")
}

func (b *EcommerceBridge) GetApiKey(ctx context.Context, username, password, tokenUrl string) (string, error) {
	return b.client.GetApiKey(ctx, username, password, tokenUrl)
}

func (b *EcommerceBridge) UpdateItemStock(ctx context.Context, apiUrl, apiKey, itemId string, newStock int) error {
	return b.client.UpdateItemStock(ctx, apiUrl, apiKey, itemId, newStock)
}

func (b *EcommerceBridge) GetAllItemsRaw(ctx context.Context, apiUrl, apiKey string) ([]byte, error) {
	return b.client.GetAllItemsRaw(ctx, apiUrl, apiKey)
}

func (b *EcommerceBridge) CreateEcommerceCustomer(ctx context.Context, apiUrl, apiKey string, customer *EcommerceCustomer) (*EcommerceCustomerResponse, error) {
	fmt.Printf("[ECOMMERCE] Creating customer - Email: %s, URL: %s\n", customer.Email, apiUrl)

	customerRequest := EcommerceCustomerRequest{
		Customers: []EcommerceCustomer{*customer},
	}

	customerData, err := json.Marshal(customerRequest)
	if err != nil {
		fmt.Printf("[ECOMMERCE] ERROR: Failed to marshal customer data: %v\n", err)
		return nil, fmt.Errorf("failed to marshal customer data: %w", err)
	}

	respBody, err := b.client.CreateEcommerceCustomer(ctx, apiUrl, apiKey, customerData)
	if err != nil {
		fmt.Printf("[ECOMMERCE] ERROR: Failed to create customer API call: %v\n", err)
		return nil, fmt.Errorf("failed to create customer: %w", err)
	}

	type CustomerCreationResponse struct {
		Customers []struct {
			ID int `json:"id"`
		} `json:"customers"`
	}

	var response CustomerCreationResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		fmt.Printf("[ECOMMERCE] ERROR: Failed to unmarshal customer response: %v\n", err)
		return nil, fmt.Errorf("failed to unmarshal customer response: %w", err)
	}

	if len(response.Customers) == 0 {
		fmt.Printf("[ECOMMERCE] ERROR: No customer created in response\n")
		return nil, fmt.Errorf("no customer created in response")
	}

	fmt.Printf("[ECOMMERCE] SUCCESS: Customer created with ID: %d\n", response.Customers[0].ID)
	return &EcommerceCustomerResponse{
		ID:      response.Customers[0].ID,
		Success: true,
		Message: "Customer created successfully",
	}, nil
}

func (b *EcommerceBridge) CreateEcommerceOrder(ctx context.Context, apiUrl, apiKey string, order *EcommerceOrder) (*EcommerceOrderResponse, error) {
	fmt.Printf("[ECOMMERCE] Creating order - CustomerID: %d, Total: %.2f\n", order.CustomerID, order.OrderTotal)

	orderRequest := EcommerceOrderRequest{
		Order: *order,
	}

	orderData, err := json.Marshal(orderRequest)
	if err != nil {
		fmt.Printf("[ECOMMERCE] ERROR: Failed to marshal order data: %v\n", err)
		return nil, fmt.Errorf("failed to marshal order data: %w", err)
	}

	respBody, err := b.client.CreateEcommerceOrder(ctx, apiUrl, apiKey, orderData)
	if err != nil {
		fmt.Printf("[ECOMMERCE] ERROR: Failed to create order API call: %v\n", err)
		return nil, fmt.Errorf("failed to create order: %w", err)
	}

	type OrderCreationResponse struct {
		ID int `json:"id"`
	}

	var response OrderCreationResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		fmt.Printf("[ECOMMERCE] ERROR: Failed to unmarshal order response: %v\n", err)
		return nil, fmt.Errorf("failed to unmarshal order response: %w", err)
	}

	fmt.Printf("[ECOMMERCE] SUCCESS: Order created with ID: %d\n", response.ID)
	return &EcommerceOrderResponse{
		ID:      response.ID,
		Success: true,
		Message: "Order created successfully",
	}, nil
}

func NewEcommerceService() EcommerceService {
	return NewEcommerceBridge()
}
