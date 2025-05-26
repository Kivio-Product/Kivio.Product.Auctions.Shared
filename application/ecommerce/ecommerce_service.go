package services

import (
	"context"

	customerDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/customer"
	itemDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
	infrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/integration"
)

type EcommerceService interface {
	GetItems(ctx context.Context) ([]itemDomain.Item, error)
	GetItemByID(ctx context.Context, id string) (*itemDomain.Item, error)
	GetCustomers(ctx context.Context, apiUrl, apiKey string) ([]customerDomain.Customer, error)
	GetCustomerByID(ctx context.Context, id string) (*customerDomain.Customer, error)
	GetApiKey(ctx context.Context, username, password, tokenUrl string) (string, error)
}

type ecommerceService struct {
	repo infrastructure.EcommerceRepository
}

func NewEcommerceService(repo infrastructure.EcommerceRepository) EcommerceService {
	return &ecommerceService{
		repo: repo,
	}
}

func (s *ecommerceService) GetItems(ctx context.Context) ([]itemDomain.Item, error) {
	arg2 := "defaultArg2" // TODO: Replace with actual logic to get arg2
	arg3 := "defaultArg3" // TODO: Replace with actual logic to get arg3
	return s.repo.GetItems(arg2, arg3)
}

func (s *ecommerceService) GetItemByID(ctx context.Context, id string) (*itemDomain.Item, error) {
	arg2 := "defaultArg2"
	arg3 := "defaultArg3"
	return s.repo.GetItemByID(id, arg2, arg3)
}

func (s *ecommerceService) GetCustomers(ctx context.Context, apiUrl, apiKey string) ([]customerDomain.Customer, error) {
	return s.repo.GetCustomers(apiUrl, apiKey)
}

func (s *ecommerceService) GetCustomerByID(ctx context.Context, id string) (*customerDomain.Customer, error) {
	arg2 := "defaultArg2"
	arg3 := "defaultArg3"
	return s.repo.GetCustomerByID(id, arg2, arg3)
}

func (s *ecommerceService) GetApiKey(ctx context.Context, username, password, tokenUrl string) (string, error) {
	return s.repo.GetApiKey(username, password, tokenUrl)
}
