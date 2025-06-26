package services

import (
	"context"

	customerDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/customer"
	itemDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
	infrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/integration"
)

type EcommerceService interface {
	GetItems(ctx context.Context, apiUrl, apiKey string, page, limit int) ([]itemDomain.Item, error)
	GetItemsRaw(ctx context.Context, apiUrl, apiKey string, page, limit int, publishedStatus bool) ([]byte, error)
	GetItemByID(ctx context.Context, id, apiUrl, apiKey string) (*itemDomain.Item, error)
	GetItemByIDRaw(ctx context.Context, id, apiUrl, apiKey string) ([]byte, error)
	GetCustomers(ctx context.Context, apiUrl, apiKey string) ([]customerDomain.Customer, error)
	GetCustomerByID(ctx context.Context, id, apiUrl, apiKey string) (*customerDomain.Customer, error)
	GetApiKey(ctx context.Context, username, password, tokenUrl string) (string, error)
	UpdateItemStock(ctx context.Context, apiUrl, apiKey, itemId string, newStock int64) error
	GetAllItemsRaw(ctx context.Context, apiUrl, apiKey string) ([]byte, error)
}

type ecommerceService struct {
	repo infrastructure.EcommerceRepository
}

func NewEcommerceService(repo infrastructure.EcommerceRepository) EcommerceService {
	return &ecommerceService{
		repo: repo,
	}
}

func (s *ecommerceService) GetItems(ctx context.Context, apiUrl, apiKey string, page, limit int) ([]itemDomain.Item, error) {
	return s.repo.GetItems(apiUrl, apiKey, page, limit)
}

func (s *ecommerceService) GetItemsRaw(ctx context.Context, apiUrl, apiKey string, page, limit int, publishedStatus bool) ([]byte, error) {
	return s.repo.GetItemsRaw(apiUrl, apiKey, page, limit, publishedStatus)
}

func (s *ecommerceService) GetItemByID(ctx context.Context, id, apiUrl, apiKey string) (*itemDomain.Item, error) {
	return s.repo.GetItemByID(id, apiUrl, apiKey)
}

func (s *ecommerceService) GetItemByIDRaw(ctx context.Context, id, apiUrl, apiKey string) ([]byte, error) {
	return s.repo.GetItemByIDRaw(apiUrl, apiKey, id)
}

func (s *ecommerceService) GetCustomers(ctx context.Context, apiUrl, apiKey string) ([]customerDomain.Customer, error) {
	return s.repo.GetCustomers(apiUrl, apiKey)
}

func (s *ecommerceService) GetCustomerByID(ctx context.Context, id, apiUrl, apiKey string) (*customerDomain.Customer, error) {
	return s.repo.GetCustomerByID(id, apiUrl, apiKey)
}

func (s *ecommerceService) GetApiKey(ctx context.Context, username, password, tokenUrl string) (string, error) {
	return s.repo.GetApiKey(username, password, tokenUrl)
}

func (s *ecommerceService) UpdateItemStock(ctx context.Context, apiUrl, apiKey, itemId string, newStock int64) error {
	return s.repo.UpdateItemStock(apiUrl, apiKey, itemId, newStock)
}

func (s *ecommerceService) GetAllItemsRaw(ctx context.Context, apiUrl, apiKey string) ([]byte, error) {
	return s.repo.GetAllItemsRaw(apiUrl, apiKey)
}
