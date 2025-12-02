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

type EcommerceCustomerBasic struct {
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	FirstName    string    `json:"first_name"`
	LastName     string    `json:"last_name"`
	Active       bool      `json:"active"`
	CreatedOnUTC time.Time `json:"created_on_utc"`
	RoleIDs      []int     `json:"role_ids"`
}

type EcommerceCustomerRequest struct {
	Customer EcommerceCustomerBasic `json:"customer"`
}

type EcommerceCustomerResponse struct {
	ID      int    `json:"id"`
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type EcommerceBillingAddressResponse struct {
	ID      int    `json:"id"`
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type EcommerceShippingAddressResponse struct {
	ID      int    `json:"id"`
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type EcommerceShoppingCartItem struct {
	Quantity         int       `json:"quantity"`
	CreatedOnUTC     time.Time `json:"created_on_utc"`
	ShoppingCartType string    `json:"shopping_cart_type"`
	ProductID        int       `json:"product_id"`
	CustomerID       int       `json:"customer_id"`
}

type EcommerceShoppingCartItemRequest struct {
	ShoppingCartItem EcommerceShoppingCartItem `json:"shopping_cart_item"`
}

type EcommerceShoppingCartItemResponse struct {
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

type EcommerceOrderItemResponse struct {
	ID               int     `json:"id"`
	ProductID        int     `json:"product_id"`
	UnitPriceInclTax float64 `json:"unit_price_incl_tax"`
	UnitPriceExclTax float64 `json:"unit_price_excl_tax"`
}

type EcommerceOrderResponse struct {
	ID                    int                          `json:"id"`
	OrderItemID           int                          `json:"order_item_id"`
	OrderItemsCount       int                          `json:"order_items_count"`
	OrderItems            []EcommerceOrderItemResponse `json:"order_items"`
	SiigoInvoicePublicURL string                       `json:"siigo_invoice_public_url"`
	Success               bool                         `json:"success"`
	Message               string                       `json:"message"`
}

type EcommerceSimpleAddress struct {
	ID int `json:"id"`
}

type EcommerceSimpleOrder struct {
	StoreID                 int                     `json:"store_id"`
	PaymentMethodSystemName string                  `json:"payment_method_system_name"`
	CustomerCurrencyCode    string                  `json:"customer_currency_code"`
	CurrencyRate            float64                 `json:"currency_rate"`
	OrderTax                float64                 `json:"order_tax"`
	OrderTotal              float64                 `json:"order_total"`
	PaidDateUTC             time.Time               `json:"paid_date_utc"`
	CreatedOnUTC            time.Time               `json:"created_on_utc"`
	CustomerID              int                     `json:"customer_id"`
	BillingAddress          *EcommerceSimpleAddress `json:"billing_address"`
	ShippingAddress         *EcommerceSimpleAddress `json:"shipping_address"`
}

type EcommerceSimpleOrderRequest struct {
	Order EcommerceSimpleOrder `json:"order"`
}

type EcommerceStore struct {
	Name       string `json:"name"`
	URL        string `json:"url"`
	SSLEnabled bool   `json:"ssl_enabled"`
	ID         int    `json:"id"`
}

type EcommerceStoresResponse struct {
	Stores []EcommerceStore `json:"stores"`
}

type EcommerceOrderUpdate struct {
	OrderTotal           float64                 `json:"order_total"`
	OrderSubtotalInclTax float64                 `json:"order_subtotal_incl_tax"`
	OrderSubtotalExclTax float64                 `json:"order_subtotal_excl_tax"`
	ID                   int                     `json:"id"`
	CustomerID           int                     `json:"customer_id"`
	BillingAddress       *EcommerceSimpleAddress `json:"billing_address"`
	ShippingAddress      *EcommerceSimpleAddress `json:"shipping_address"`
}

type EcommerceOrderUpdateRequest struct {
	ObjectPropertyNameValuePairs map[string]interface{} `json:"ObjectPropertyNameValuePairs"`
	Order                        EcommerceOrderUpdate   `json:"order"`
}

type ItemQuantity struct {
	ItemID   string `json:"item_id"`
	Quantity int    `json:"quantity"`
}

type ItemVerificationDetail struct {
	ItemID   string  `json:"item_id"`
	Price    float64 `json:"price"`
	Quantity int     `json:"quantity"`
	Subtotal float64 `json:"subtotal"`
	ItemName string  `json:"item_name"`
}

type OrderVerificationResult struct {
	IsValid    bool                     `json:"is_valid"`
	TotalItems int                      `json:"total_items"`
	GrandTotal float64                  `json:"grand_total"`
	Details    []ItemVerificationDetail `json:"details"`
	MinTotal   float64                  `json:"min_total"`
}

type EcommerceBridge struct {
	client ecommerceClient.EcommerceService
}

func NewEcommerceBridge() *EcommerceBridge {
	return &EcommerceBridge{
		client: ecommerceClient.NewEcommerceService(),
	}
}

type ItemWithDetails struct {
	itemDomain.Item
	Availability int     `json:"availability"`
	Price        float64 `json:"price"`
}

type EcommerceService interface {
	GetItems(ctx context.Context, apiUrl, apiKey string, page, limit int) ([]itemDomain.Item, error)
	GetItemsWithLastItem(ctx context.Context, apiUrl, apiKey string, lastItemID string, limit int, filters map[string]string) ([]itemDomain.Item, string, error)
	GetItemsRaw(ctx context.Context, apiUrl, apiKey string, page, limit int, publishedStatus bool) ([]byte, error)
	GetItemByID(ctx context.Context, id, apiUrl, apiKey string) (*itemDomain.Item, error)
	GetItemByIDWithDetails(ctx context.Context, id, apiUrl, apiKey string) (*ItemWithDetails, error)
	GetItemByIDRaw(ctx context.Context, id, apiUrl, apiKey string) ([]byte, error)
	GetCustomers(ctx context.Context, apiUrl, apiKey string) ([]customerDomain.Customer, error)
	GetCustomerByID(ctx context.Context, id, apiUrl, apiKey string) (*customerDomain.Customer, error)
	GetCustomerEmails(ctx context.Context, apiUrl, apiKey string) ([]string, error)
	GetApiKey(ctx context.Context, username, password, tokenUrl string) (string, error)
	UpdateItemStock(ctx context.Context, apiUrl, apiKey, itemId string, newStock int) error
	GetAllItemsRaw(ctx context.Context, apiUrl, apiKey string) ([]byte, error)
	GetStores(ctx context.Context, apiUrl, apiKey string) (*EcommerceStoresResponse, error)
	CreateEcommerceCustomer(ctx context.Context, apiUrl, apiKey string, customer *EcommerceCustomer) (*EcommerceCustomerResponse, error)
	CreateEcommerceBillingAddress(ctx context.Context, apiUrl, apiKey string, customerID int, address *EcommerceAddress) (*EcommerceBillingAddressResponse, error)
	CreateEcommerceShippingAddress(ctx context.Context, apiUrl, apiKey string, customerID int, address *EcommerceAddress) (*EcommerceShippingAddressResponse, error)
	DeleteEcommerceShoppingCart(ctx context.Context, apiUrl, apiKey string, customerID int) error
	CreateEcommerceShoppingCartItem(ctx context.Context, apiUrl, apiKey string, cartItem *EcommerceShoppingCartItem) (*EcommerceShoppingCartItemResponse, error)
	CreateEcommerceOrder(ctx context.Context, apiUrl, apiKey string, order *EcommerceOrder) (*EcommerceOrderResponse, error)
	CreateEcommerceSimpleOrder(ctx context.Context, apiUrl, apiKey string, order *EcommerceSimpleOrder) (*EcommerceOrderResponse, error)
	CountEcommerceItems(ctx context.Context, apiUrl, apiKey string, filters map[string]string) (int64, error)
	UpdateOrderItemPrice(ctx context.Context, apiUrl, apiKey string, orderID, itemID int, orderItem *EcommerceOrderItem) error
	UpdateOrder(ctx context.Context, apiUrl, apiKey string, orderID int, orderUpdate *EcommerceOrderUpdate) error
	VerifyOrderTotal(ctx context.Context, items []ItemQuantity, apiUrl, apiKey string, minTotal float64) (*OrderVerificationResult, error)
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

func (b *EcommerceBridge) CountEcommerceItems(ctx context.Context, apiUrl, apiKey string, filters map[string]string) (int64, error) {
	total, err := b.client.CountEcommerceItems(ctx, apiUrl, apiKey, filters)
	if err != nil {
		return 0, err
	}

	return total, nil
}

func (b *EcommerceBridge) GetItemsWithLastItem(ctx context.Context, apiUrl, apiKey string, lastItemID string, limit int, filters map[string]string) ([]itemDomain.Item, string, error) {
	items, nextItemID, err := b.client.GetItemsWithLastItem(ctx, apiUrl, apiKey, lastItemID, limit, filters)
	if err != nil {
		return nil, "", err
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
			StockQuantity: item.StockQuantity,
		}
	}
	return result, nextItemID, nil
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

func (b *EcommerceBridge) GetItemByIDWithDetails(ctx context.Context, id, apiUrl, apiKey string) (*ItemWithDetails, error) {
	itemDetails, err := b.client.GetItemByIDWithDetails(ctx, id, apiUrl, apiKey)
	if err != nil {
		return nil, err
	}

	return &ItemWithDetails{
		Item: itemDomain.Item{
			ItemId:        itemDetails.Item.ItemId,
			Name:          itemDetails.Item.Name,
			Description:   itemDetails.Item.Description,
			ExternalId:    itemDetails.Item.ExternalId,
			PointOfSaleId: itemDetails.Item.PointOfSaleId,
			Url:           itemDetails.Item.Url,
			Source:        itemDetails.Item.Source,
		},
		Availability: itemDetails.Availability,
		Price:        itemDetails.Price,
	}, nil
}

func (b *EcommerceBridge) GetItemByIDRaw(ctx context.Context, id, apiUrl, apiKey string) ([]byte, error) {
	return b.client.GetItemByIDRaw(ctx, id, apiUrl, apiKey)
}

func (b *EcommerceBridge) GetCustomers(ctx context.Context, apiUrl, apiKey string) ([]customerDomain.Customer, error) {
	customers, err := b.client.GetCustomers(ctx, apiUrl, apiKey)
	if err != nil {
		return nil, err
	}

	result := make([]customerDomain.Customer, len(customers))
	for i, c := range customers {
		result[i] = customerDomain.Customer{
			Email: c.Email,
		}
	}
	return result, nil
}

func (b *EcommerceBridge) GetCustomerByID(ctx context.Context, id, apiUrl, apiKey string) (*customerDomain.Customer, error) {
	return nil, fmt.Errorf("GetCustomerByID not implemented - customer domain structure changed")
}

func (b *EcommerceBridge) GetCustomerEmails(ctx context.Context, apiUrl, apiKey string) ([]string, error) {
	emailSet := make(map[string]struct{})

	customers, err := b.client.GetCustomers(ctx, apiUrl, apiKey)
	if err == nil {
		for _, c := range customers {
			if c.Email != "" {
				emailSet[c.Email] = struct{}{}
			}
		}
	}

	orderEmails, err := b.client.GetOrderEmails(ctx, apiUrl, apiKey)
	if err == nil {
		for _, email := range orderEmails {
			if email != "" {
				emailSet[email] = struct{}{}
			}
		}
	}

	emails := make([]string, 0, len(emailSet))
	for email := range emailSet {
		emails = append(emails, email)
	}

	return emails, nil
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

	fmt.Printf("[ECOMMERCE] Customer received: %+v\n", customer)
	fmt.Printf("[ECOMMERCE] Customer RoleIDs: %+v\n", customer.RoleIDs)

	basicCustomer := EcommerceCustomerBasic{
		Username:     customer.Username,
		Email:        customer.Email,
		FirstName:    customer.FirstName,
		LastName:     customer.LastName,
		Active:       customer.Active,
		CreatedOnUTC: customer.CreatedOnUTC,
		RoleIDs:      customer.RoleIDs,
	}

	fmt.Printf("[ECOMMERCE] BasicCustomer created: %+v\n", basicCustomer)
	fmt.Printf("[ECOMMERCE] BasicCustomer RoleIDs: %+v\n", basicCustomer.RoleIDs)

	customerRequest := EcommerceCustomerRequest{
		Customer: basicCustomer,
	}

	customerData, err := json.Marshal(customerRequest)
	if err != nil {
		fmt.Printf("[ECOMMERCE] ERROR: Failed to marshal customer data: %v\n", err)
		return nil, fmt.Errorf("failed to marshal customer data: %w", err)
	}

	fmt.Printf("[ECOMMERCE] Final customer JSON to be sent: %s\n", string(customerData))

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
		fmt.Printf("[ECOMMERCE] ERROR: No customers in response\n")
		return nil, fmt.Errorf("no customers in response")
	}

	if response.Customers[0].ID == 0 {
		fmt.Printf("[ECOMMERCE] ERROR: No customer ID in response\n")
		return nil, fmt.Errorf("no customer ID in response")
	}

	fmt.Printf("[ECOMMERCE] SUCCESS: Customer created with ID: %d\n", response.Customers[0].ID)
	return &EcommerceCustomerResponse{
		ID:      response.Customers[0].ID,
		Success: true,
		Message: "Customer created successfully",
	}, nil
}

func (b *EcommerceBridge) CreateEcommerceBillingAddress(ctx context.Context, apiUrl, apiKey string, customerID int, address *EcommerceAddress) (*EcommerceBillingAddressResponse, error) {
	fmt.Printf("[ECOMMERCE] Creating billing address for customer %d\n", customerID)

	addressData, err := json.Marshal(address)
	if err != nil {
		fmt.Printf("[ECOMMERCE] ERROR: Failed to marshal address data: %v\n", err)
		return nil, fmt.Errorf("failed to marshal address data: %w", err)
	}

	respBody, err := b.client.CreateEcommerceBillingAddress(ctx, apiUrl, apiKey, customerID, addressData)
	if err != nil {
		fmt.Printf("[ECOMMERCE] ERROR: Failed to create billing address API call: %v\n", err)
		return nil, fmt.Errorf("failed to create billing address: %w", err)
	}

	type BillingAddressCreationResponse struct {
		ID int `json:"id"`
	}

	var response BillingAddressCreationResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		fmt.Printf("[ECOMMERCE] ERROR: Failed to unmarshal billing address response: %v\n", err)
		return nil, fmt.Errorf("failed to unmarshal billing address response: %w", err)
	}

	fmt.Printf("[ECOMMERCE] SUCCESS: Billing address created with ID: %d\n", response.ID)
	return &EcommerceBillingAddressResponse{
		ID:      response.ID,
		Success: true,
		Message: "Billing address created successfully",
	}, nil
}

func (b *EcommerceBridge) CreateEcommerceShippingAddress(ctx context.Context, apiUrl, apiKey string, customerID int, address *EcommerceAddress) (*EcommerceShippingAddressResponse, error) {
	fmt.Printf("[ECOMMERCE] Creating shipping address for customer %d\n", customerID)

	addressData, err := json.Marshal(address)
	if err != nil {
		fmt.Printf("[ECOMMERCE] ERROR: Failed to marshal address data: %v\n", err)
		return nil, fmt.Errorf("failed to marshal address data: %w", err)
	}

	respBody, err := b.client.CreateEcommerceShippingAddress(ctx, apiUrl, apiKey, customerID, addressData)
	if err != nil {
		fmt.Printf("[ECOMMERCE] ERROR: Failed to create shipping address API call: %v\n", err)
		return nil, fmt.Errorf("failed to create shipping address: %w", err)
	}

	type ShippingAddressCreationResponse struct {
		ID int `json:"id"`
	}

	var response ShippingAddressCreationResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		fmt.Printf("[ECOMMERCE] ERROR: Failed to unmarshal shipping address response: %v\n", err)
		return nil, fmt.Errorf("failed to unmarshal shipping address response: %w", err)
	}

	fmt.Printf("[ECOMMERCE] SUCCESS: Shipping address created with ID: %d\n", response.ID)
	return &EcommerceShippingAddressResponse{
		ID:      response.ID,
		Success: true,
		Message: "Shipping address created successfully",
	}, nil
}

func (b *EcommerceBridge) DeleteEcommerceShoppingCart(ctx context.Context, apiUrl, apiKey string, customerID int) error {
	fmt.Printf("[ECOMMERCE] Deleting shopping cart for customer %d\n", customerID)

	err := b.client.DeleteEcommerceShoppingCart(ctx, apiUrl, apiKey, customerID)
	if err != nil {
		fmt.Printf("[ECOMMERCE] ERROR: Failed to delete shopping cart: %v\n", err)
		return fmt.Errorf("failed to delete shopping cart: %w", err)
	}

	fmt.Printf("[ECOMMERCE] SUCCESS: Shopping cart deleted for customer %d\n", customerID)
	return nil
}

func (b *EcommerceBridge) CreateEcommerceShoppingCartItem(ctx context.Context, apiUrl, apiKey string, cartItem *EcommerceShoppingCartItem) (*EcommerceShoppingCartItemResponse, error) {
	fmt.Printf("[ECOMMERCE] Creating shopping cart item - CustomerID: %d, ProductID: %d\n", cartItem.CustomerID, cartItem.ProductID)

	cartItemRequest := EcommerceShoppingCartItemRequest{
		ShoppingCartItem: *cartItem,
	}

	cartItemData, err := json.Marshal(cartItemRequest)
	if err != nil {
		fmt.Printf("[ECOMMERCE] ERROR: Failed to marshal shopping cart item data: %v\n", err)
		return nil, fmt.Errorf("failed to marshal shopping cart item data: %w", err)
	}

	respBody, err := b.client.CreateEcommerceShoppingCartItem(ctx, apiUrl, apiKey, cartItemData)
	if err != nil {
		fmt.Printf("[ECOMMERCE] ERROR: Failed to create shopping cart item API call: %v\n", err)
		return nil, fmt.Errorf("failed to create shopping cart item: %w", err)
	}

	type ShoppingCartItemCreationResponse struct {
		ID int `json:"id"`
	}

	var response ShoppingCartItemCreationResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		fmt.Printf("[ECOMMERCE] ERROR: Failed to unmarshal shopping cart item response: %v\n", err)
		return nil, fmt.Errorf("failed to unmarshal shopping cart item response: %w", err)
	}

	fmt.Printf("[ECOMMERCE] SUCCESS: Shopping cart item created with ID: %d\n", response.ID)
	return &EcommerceShoppingCartItemResponse{
		ID:      response.ID,
		Success: true,
		Message: "Shopping cart item created successfully",
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

	type OrderItemResponse struct {
		ID               int     `json:"id"`
		ProductID        int     `json:"product_id"`
		UnitPriceInclTax float64 `json:"unit_price_incl_tax"`
		UnitPriceExclTax float64 `json:"unit_price_excl_tax"`
	}

	type OrderResponse struct {
		ID         int                 `json:"id"`
		OrderItems []OrderItemResponse `json:"order_items"`
	}

	type OrderCreationResponse struct {
		Orders []OrderResponse `json:"orders"`
	}

	var response OrderCreationResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		fmt.Printf("[ECOMMERCE] ERROR: Failed to unmarshal order response: %v\n", err)
		fmt.Printf("[ECOMMERCE] Response body: %s\n", string(respBody))
		return nil, fmt.Errorf("failed to unmarshal order response: %w", err)
	}

	if len(response.Orders) == 0 {
		fmt.Printf("[ECOMMERCE] ERROR: No orders in response\n")
		return nil, fmt.Errorf("no orders in response")
	}

	orderID := response.Orders[0].ID
	var firstOrderItemID int
	var orderItems []EcommerceOrderItemResponse

	if len(response.Orders[0].OrderItems) > 0 {
		firstOrderItemID = response.Orders[0].OrderItems[0].ID

		for _, item := range response.Orders[0].OrderItems {
			orderItems = append(orderItems, EcommerceOrderItemResponse{
				ID:               item.ID,
				ProductID:        item.ProductID,
				UnitPriceInclTax: item.UnitPriceInclTax,
				UnitPriceExclTax: item.UnitPriceExclTax,
			})
		}

		fmt.Printf("[ECOMMERCE] SUCCESS: Order created with ID: %d, First Order Item ID: %d, UnitPriceInclTax: %.2f, UnitPriceExclTax: %.2f\n",
			orderID, firstOrderItemID, orderItems[0].UnitPriceInclTax, orderItems[0].UnitPriceExclTax)
	} else {
		fmt.Printf("[ECOMMERCE] SUCCESS: Order created with ID: %d, no order items found\n", orderID)
	}

	return &EcommerceOrderResponse{
		ID:              orderID,
		OrderItemID:     firstOrderItemID,
		OrderItemsCount: len(response.Orders[0].OrderItems),
		OrderItems:      orderItems,
		Success:         true,
		Message:         "Order created successfully",
	}, nil
}

func (b *EcommerceBridge) CreateEcommerceSimpleOrder(ctx context.Context, apiUrl, apiKey string, order *EcommerceSimpleOrder) (*EcommerceOrderResponse, error) {
	fmt.Printf("[ECOMMERCE] Creating simple order - CustomerID: %d, Total: %.2f\n", order.CustomerID, order.OrderTotal)

	orderRequest := EcommerceSimpleOrderRequest{
		Order: *order,
	}

	orderData, err := json.Marshal(orderRequest)
	if err != nil {
		fmt.Printf("[ECOMMERCE] ERROR: Failed to marshal simple order data: %v\n", err)
		return nil, fmt.Errorf("failed to marshal simple order data: %w", err)
	}

	respBody, err := b.client.CreateEcommerceOrder(ctx, apiUrl, apiKey, orderData)
	if err != nil {
		fmt.Printf("[ECOMMERCE] ERROR: Failed to create simple order API call: %v\n", err)
		return nil, fmt.Errorf("failed to create simple order: %w", err)
	}

	type OrderItemResponse struct {
		ID               int     `json:"id"`
		ProductID        int     `json:"product_id"`
		UnitPriceInclTax float64 `json:"unit_price_incl_tax"`
		UnitPriceExclTax float64 `json:"unit_price_excl_tax"`
	}

	type OrderResponse struct {
		ID                    int                 `json:"id"`
		OrderItems            []OrderItemResponse `json:"order_items"`
		SiigoInvoicePublicURL string              `json:"siigo_invoice_public_url"`
	}

	type SimpleOrderCreationResponse struct {
		Orders []OrderResponse `json:"orders"`
	}

	var response SimpleOrderCreationResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		fmt.Printf("[ECOMMERCE] ERROR: Failed to unmarshal simple order response: %v\n", err)
		fmt.Printf("[ECOMMERCE] Response body: %s\n", string(respBody))
		return nil, fmt.Errorf("failed to unmarshal simple order response: %w", err)
	}

	if len(response.Orders) == 0 {
		fmt.Printf("[ECOMMERCE] ERROR: No orders in response\n")
		return nil, fmt.Errorf("no orders in response")
	}

	orderID := response.Orders[0].ID
	var firstOrderItemID int
	var orderItems []EcommerceOrderItemResponse

	if len(response.Orders[0].OrderItems) > 0 {
		firstOrderItemID = response.Orders[0].OrderItems[0].ID

		for _, item := range response.Orders[0].OrderItems {
			orderItems = append(orderItems, EcommerceOrderItemResponse{
				ID:               item.ID,
				ProductID:        item.ProductID,
				UnitPriceInclTax: item.UnitPriceInclTax,
				UnitPriceExclTax: item.UnitPriceExclTax,
			})
		}

		fmt.Printf("[ECOMMERCE] SUCCESS: Simple order created with ID: %d, First Order Item ID: %d, UnitPriceInclTax: %.2f, UnitPriceExclTax: %.2f\n",
			orderID, firstOrderItemID, orderItems[0].UnitPriceInclTax, orderItems[0].UnitPriceExclTax)
	} else {
		fmt.Printf("[ECOMMERCE] SUCCESS: Simple order created with ID: %d, no order items found\n", orderID)
	}

	return &EcommerceOrderResponse{
		ID:                    orderID,
		OrderItemID:           firstOrderItemID,
		Success:               true,
		Message:               "Simple order created successfully",
		OrderItemsCount:       len(response.Orders[0].OrderItems),
		OrderItems:            orderItems,
		SiigoInvoicePublicURL: response.Orders[0].SiigoInvoicePublicURL,
	}, nil
}

func (b *EcommerceBridge) UpdateOrderItemPrice(ctx context.Context, apiUrl, apiKey string, orderID, itemID int, orderItem *EcommerceOrderItem) error {
	fmt.Printf("[ECOMMERCE] Updating order item price - OrderID: %d, ItemID: %d\n", orderID, itemID)

	type OrderItemUpdateRequest struct {
		ObjectPropertyNameValuePairs map[string]interface{} `json:"ObjectPropertyNameValuePairs"`
		OrderItem                    EcommerceOrderItem     `json:"order_item"`
	}

	updateRequest := OrderItemUpdateRequest{
		ObjectPropertyNameValuePairs: map[string]interface{}{},
		OrderItem:                    *orderItem,
	}

	orderItemData, err := json.Marshal(updateRequest)
	if err != nil {
		fmt.Printf("[ECOMMERCE] ERROR: Failed to marshal order item data: %v\n", err)
		return fmt.Errorf("failed to marshal order item data: %w", err)
	}

	err = b.client.UpdateOrderItemPrice(ctx, apiUrl, apiKey, orderID, itemID, orderItemData)
	if err != nil {
		fmt.Printf("[ECOMMERCE] ERROR: Failed to update order item price: %v\n", err)
		return fmt.Errorf("failed to update order item price: %w", err)
	}

	fmt.Printf("[ECOMMERCE] SUCCESS: Order item price updated\n")
	return nil
}

func (b *EcommerceBridge) GetStores(ctx context.Context, apiUrl, apiKey string) (*EcommerceStoresResponse, error) {
	fmt.Printf("[ECOMMERCE] Getting stores from %s\n", apiUrl)

	respBody, err := b.client.GetStores(ctx, apiUrl, apiKey)
	if err != nil {
		fmt.Printf("[ECOMMERCE] ERROR: Failed to get stores: %v\n", err)
		return nil, fmt.Errorf("failed to get stores: %w", err)
	}

	var response EcommerceStoresResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		fmt.Printf("[ECOMMERCE] ERROR: Failed to unmarshal stores response: %v\n", err)
		return nil, fmt.Errorf("failed to unmarshal stores response: %w", err)
	}

	fmt.Printf("[ECOMMERCE] SUCCESS: Retrieved %d stores\n", len(response.Stores))
	return &response, nil
}

func (b *EcommerceBridge) UpdateOrder(ctx context.Context, apiUrl, apiKey string, orderID int, orderUpdate *EcommerceOrderUpdate) error {
	fmt.Printf("[ECOMMERCE] Updating order %d - Total: %.2f, SubtotalInclTax: %.2f, SubtotalExclTax: %.2f\n",
		orderID, orderUpdate.OrderTotal, orderUpdate.OrderSubtotalInclTax, orderUpdate.OrderSubtotalExclTax)

	updateRequest := EcommerceOrderUpdateRequest{
		ObjectPropertyNameValuePairs: map[string]interface{}{},
		Order:                        *orderUpdate,
	}

	orderData, err := json.Marshal(updateRequest)
	if err != nil {
		fmt.Printf("[ECOMMERCE] ERROR: Failed to marshal order update data: %v\n", err)
		return fmt.Errorf("failed to marshal order update data: %w", err)
	}

	err = b.client.UpdateOrder(ctx, apiUrl, apiKey, orderID, orderData)
	if err != nil {
		fmt.Printf("[ECOMMERCE] ERROR: Failed to update order: %v\n", err)
		return fmt.Errorf("failed to update order: %w", err)
	}

	fmt.Printf("[ECOMMERCE] SUCCESS: Order updated\n")
	return nil
}

func (b *EcommerceBridge) VerifyOrderTotal(ctx context.Context, items []ItemQuantity, apiUrl, apiKey string, minTotal float64) (*OrderVerificationResult, error) {
	fmt.Printf("[ECOMMERCE] Verifying order total for %d items with minimum total: %.2f\n", len(items), minTotal)

	result := &OrderVerificationResult{
		IsValid:    false,
		TotalItems: len(items),
		GrandTotal: 0,
		Details:    make([]ItemVerificationDetail, 0, len(items)),
		MinTotal:   minTotal,
	}

	for _, item := range items {
		itemDetails, err := b.GetItemByIDWithDetails(ctx, item.ItemID, apiUrl, apiKey)
		if err != nil {
			fmt.Printf("[ECOMMERCE] ERROR: Failed to get item details for ID %s: %v\n", item.ItemID, err)
			return nil, fmt.Errorf("failed to get item details for ID %s: %w", item.ItemID, err)
		}

		subtotal := itemDetails.Price * float64(item.Quantity)
		detail := ItemVerificationDetail{
			ItemID:   item.ItemID,
			Price:    itemDetails.Price,
			Quantity: item.Quantity,
			Subtotal: subtotal,
			ItemName: itemDetails.Name,
		}

		result.Details = append(result.Details, detail)
		result.GrandTotal += subtotal

		fmt.Printf("[ECOMMERCE] Item %s (%s) - Price: %.2f × Quantity: %d = Subtotal: %.2f\n",
			item.ItemID, itemDetails.Name, itemDetails.Price, item.Quantity, subtotal)
	}

	result.IsValid = result.GrandTotal > minTotal

	if result.IsValid {
		fmt.Printf("[ECOMMERCE] Verification PASSED - Grand Total: %.2f (minimum: %.2f)\n", result.GrandTotal, minTotal)
	} else {
		fmt.Printf("[ECOMMERCE] Verification FAILED - Grand Total: %.2f (minimum: %.2f)\n", result.GrandTotal, minTotal)
	}

	return result, nil
}

func NewEcommerceService() EcommerceService {
	return NewEcommerceBridge()
}
