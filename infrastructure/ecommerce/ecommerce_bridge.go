package ecommerce

import (
	"context"

	customerDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/customer"
	itemDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"

	ecommerceClient "github.com/Kivio-Product/Kivio.Product.Auctions.EcommerceClient"
)

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
	customers, err := b.client.GetCustomers(ctx, apiUrl, apiKey)
	if err != nil {
		return nil, err
	}

	result := make([]customerDomain.Customer, len(customers))
	for i, customer := range customers {
		result[i] = customerDomain.Customer{
			ID:        customer.ID,
			Email:     customer.Email,
			Name:      customer.Name,
			Phone:     customer.Phone,
			Address:   customer.Address,
			CreatedAt: customer.CreatedAt,
			UpdatedAt: customer.UpdatedAt,
		}
	}
	return result, nil
}

func (b *EcommerceBridge) GetCustomerByID(ctx context.Context, id, apiUrl, apiKey string) (*customerDomain.Customer, error) {
	customer, err := b.client.GetCustomerByID(ctx, id, apiUrl, apiKey)
	if err != nil {
		return nil, err
	}

	return &customerDomain.Customer{
		ID:        customer.ID,
		Email:     customer.Email,
		Name:      customer.Name,
		Phone:     customer.Phone,
		Address:   customer.Address,
		CreatedAt: customer.CreatedAt,
		UpdatedAt: customer.UpdatedAt,
	}, nil
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

func NewEcommerceService() EcommerceService {
	return NewEcommerceBridge()
}
