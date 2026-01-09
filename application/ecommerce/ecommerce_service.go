package services

import (
	"context"

	customerDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/customer"
	itemDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
	ecommerceBridge "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/ecommerce"
)

type EcommerceService interface {
	GetItems(ctx context.Context, apiUrl, apiKey string, page, limit int) ([]itemDomain.Item, error)
	GetItemsWithLastItem(ctx context.Context, apiUrl, apiKey string, lastItemID string, limit int, filters map[string]string) ([]itemDomain.Item, string, error)
	GetItemsRaw(ctx context.Context, apiUrl, apiKey string, page, limit int, publishedStatus bool) ([]byte, error)
	GetItemByID(ctx context.Context, id, apiUrl, apiKey string) (*itemDomain.Item, error)
	GetItemByIDWithDetails(ctx context.Context, id, apiUrl, apiKey string) (*ecommerceBridge.ItemWithDetails, error)
	GetItemByIDRaw(ctx context.Context, id, apiUrl, apiKey string) ([]byte, error)
	GetCustomers(ctx context.Context, apiUrl, apiKey string) ([]customerDomain.Customer, error)
	GetCustomerByID(ctx context.Context, id, apiUrl, apiKey string) (*customerDomain.Customer, error)
	GetCustomerEmails(ctx context.Context, apiUrl, apiKey string) ([]string, error)
	GetApiKey(ctx context.Context, username, password, tokenUrl string) (string, error)
	UpdateItemStock(ctx context.Context, apiUrl, apiKey, itemId string, newStock int) error
	GetAllItemsRaw(ctx context.Context, apiUrl, apiKey string) ([]byte, error)
	GetStores(ctx context.Context, apiUrl, apiKey string) (*ecommerceBridge.EcommerceStoresResponse, error)
	CreateEcommerceCustomer(ctx context.Context, apiUrl, apiKey string, customer *ecommerceBridge.EcommerceCustomer) (*ecommerceBridge.EcommerceCustomerResponse, error)
	CreateEcommerceBillingAddress(ctx context.Context, apiUrl, apiKey string, customerID int, address *ecommerceBridge.EcommerceAddress) (*ecommerceBridge.EcommerceBillingAddressResponse, error)
	CreateEcommerceShippingAddress(ctx context.Context, apiUrl, apiKey string, customerID int, address *ecommerceBridge.EcommerceAddress) (*ecommerceBridge.EcommerceShippingAddressResponse, error)
	DeleteEcommerceShoppingCart(ctx context.Context, apiUrl, apiKey string, customerID int) error
	CreateEcommerceShoppingCartItem(ctx context.Context, apiUrl, apiKey string, cartItem *ecommerceBridge.EcommerceShoppingCartItem) (*ecommerceBridge.EcommerceShoppingCartItemResponse, error)
	CreateEcommerceOrder(ctx context.Context, apiUrl, apiKey string, order *ecommerceBridge.EcommerceOrder) (*ecommerceBridge.EcommerceOrderResponse, error)
	CreateEcommerceSimpleOrder(ctx context.Context, apiUrl, apiKey string, order *ecommerceBridge.EcommerceSimpleOrder) (*ecommerceBridge.EcommerceOrderResponse, error)
	CountEcommerceItems(ctx context.Context, apiUrl, apiKey string, filters map[string]string) (int64, error)
	UpdateOrderItemPrice(ctx context.Context, apiUrl, apiKey string, orderID, itemID int, orderItem *ecommerceBridge.EcommerceOrderItem) error
	UpdateOrder(ctx context.Context, apiUrl, apiKey string, orderID int, orderUpdate *ecommerceBridge.EcommerceOrderUpdate) error
	GetOrderByID(ctx context.Context, apiUrl, apiKey string, orderID int) (*ecommerceBridge.EcommerceOrderResponse, error)
	VerifyOrderTotal(ctx context.Context, items []ecommerceBridge.ItemQuantity, apiUrl, apiKey string, minTotal float64) (*ecommerceBridge.OrderVerificationResult, error)
}

func NewEcommerceService() EcommerceService {
	return ecommerceBridge.NewEcommerceService()
}
