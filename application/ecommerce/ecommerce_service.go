package services

import (
	"context"

	customerDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/customer"
	itemDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
	ecommerceBridge "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/ecommerce"
)

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
	CreateEcommerceCustomer(ctx context.Context, apiUrl, apiKey string, customer *ecommerceBridge.EcommerceCustomer) (*ecommerceBridge.EcommerceCustomerResponse, error)
	CreateEcommerceBillingAddress(ctx context.Context, apiUrl, apiKey string, customerID int, address *ecommerceBridge.EcommerceAddress) (*ecommerceBridge.EcommerceBillingAddressResponse, error)
	CreateEcommerceShippingAddress(ctx context.Context, apiUrl, apiKey string, customerID int, address *ecommerceBridge.EcommerceAddress) (*ecommerceBridge.EcommerceShippingAddressResponse, error)
	CreateEcommerceOrder(ctx context.Context, apiUrl, apiKey string, order *ecommerceBridge.EcommerceOrder) (*ecommerceBridge.EcommerceOrderResponse, error)
}

func NewEcommerceService() EcommerceService {
	return ecommerceBridge.NewEcommerceService()
}
