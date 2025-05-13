package services

import (
	"context"

	customerDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/customer"
	itemDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
	infrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/integration"
)

type EcommerceService interface {
	GetItems(ctx context.Context) ([]itemDomain.Item, error)
	GetItemByID(ctx context.Context, id string) (*itemDomain.Item, error)
	GetCustomers(ctx context.Context) ([]customerDomain.Customer, error)
	GetCustomerByID(ctx context.Context, id string) (*customerDomain.Customer, error)
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
	return s.repo.GetItems()
}

func (s *ecommerceService) GetItemByID(ctx context.Context, id string) (*itemDomain.Item, error) {
	return s.repo.GetItemByID(id)
}

func (s *ecommerceService) GetCustomers(ctx context.Context) ([]customerDomain.Customer, error) {
	return s.repo.GetCustomers()
}

func (s *ecommerceService) GetCustomerByID(ctx context.Context, id string) (*customerDomain.Customer, error) {
	return s.repo.GetCustomerByID(id)
}
