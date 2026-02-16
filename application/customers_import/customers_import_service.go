package services

import (
	"context"
	"fmt"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/customers_import"

	customersImportInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/customers_import"
)

type CustomersImportService interface {
	GenerateCustomerImport(ctx context.Context, name, posId, typer, url string) (*domain.CustomersImport, error)
	Delete(ctx context.Context, id string) error
	GetCustomerImportByPosID(ctx context.Context, id string) ([]domain.CustomersImport, error)
}

type customersImportService struct {
	repo                  customersImportInfrastructure.CustomersImportRepository
	customerImportFactory domain.CustomersImportFactory
}

func NewCustomersImportService(
	repo customersImportInfrastructure.CustomersImportRepository,
	customerImportFactory domain.CustomersImportFactory,
) CustomersImportService {
	return &customersImportService{
		repo:                  repo,
		customerImportFactory: customerImportFactory,
	}
}

func (s *customersImportService) GenerateCustomerImport(ctx context.Context, name, posId, typer, url string) (*domain.CustomersImport, error) {
	customersImport, err := s.customerImportFactory.GenerateCustomersImport(name, posId, typer, url)
	if err != nil {
		return nil, err
	}

	err = s.repo.SaveCustomersImport(ctx, customersImport)
	if err != nil {
		return nil, err
	}

	return customersImport, nil
}

func (s *customersImportService) Delete(ctx context.Context, id string) error {
	err := s.repo.Delete(id)
	if err != nil {
		return fmt.Errorf("error deleting integration: %w", err)
	}
	return nil
}

func (s *customersImportService) GetCustomerImportByPosID(ctx context.Context, id string) ([]domain.CustomersImport, error) {
	customersImport, err := s.repo.GetCustomerImportByPosID(id)

	if err != nil {
		return nil, err
	}
	return customersImport, nil
}
