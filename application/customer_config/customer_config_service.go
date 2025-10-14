package services

import (
	"context"
	"fmt"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/customer_config"
	customerConfigInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/customer_config"
)

type CustomerConfigService interface {
	CreateCustomerConfig(ctx context.Context, input domain.CustomerConfigInput) (*domain.CustomerConfig, error)
	GetCustomerConfig(ctx context.Context, customerID, pointOfSaleID string) (*domain.CustomerConfig, error)
	UpdateCustomerConfig(ctx context.Context, customerID, pointOfSaleID string, allowMultipleItems bool) error
	DeleteCustomerConfig(ctx context.Context, customerID, pointOfSaleID string) error
	IsMultipleItemsAllowed(ctx context.Context, customerID, pointOfSaleID string) (bool, error)
	GetConfigsByPointOfSale(ctx context.Context, pointOfSaleID string) ([]domain.CustomerConfig, error)
}

type customerConfigService struct {
	repo    customerConfigInfrastructure.CustomerConfigRepository
	factory domain.CustomerConfigFactory
}

func NewCustomerConfigService(repo customerConfigInfrastructure.CustomerConfigRepository, factory domain.CustomerConfigFactory) CustomerConfigService {
	return &customerConfigService{
		repo:    repo,
		factory: factory,
	}
}

func (s *customerConfigService) CreateCustomerConfig(ctx context.Context, input domain.CustomerConfigInput) (*domain.CustomerConfig, error) {
	config, err := s.factory.CreateCustomerConfig(input)
	if err != nil {
		return nil, fmt.Errorf("failed to create customer config: %w", err)
	}

	err = s.repo.Save(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to save customer config: %w", err)
	}

	return config, nil
}

func (s *customerConfigService) GetCustomerConfig(ctx context.Context, customerID, pointOfSaleID string) (*domain.CustomerConfig, error) {
	config, err := s.repo.GetByCustomerID(ctx, customerID, pointOfSaleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get customer config: %w", err)
	}

	return config, nil
}

func (s *customerConfigService) UpdateCustomerConfig(ctx context.Context, customerID, pointOfSaleID string, allowMultipleItems bool) error {
	config, err := s.repo.GetByCustomerID(ctx, customerID, pointOfSaleID)
	if err != nil {
		return fmt.Errorf("failed to get customer config for update: %w", err)
	}

	err = config.Update(allowMultipleItems)
	if err != nil {
		return fmt.Errorf("failed to update customer config: %w", err)
	}

	err = s.repo.Update(ctx, config)
	if err != nil {
		return fmt.Errorf("failed to save updated customer config: %w", err)
	}

	return nil
}

func (s *customerConfigService) DeleteCustomerConfig(ctx context.Context, customerID, pointOfSaleID string) error {
	err := s.repo.Delete(ctx, customerID, pointOfSaleID)
	if err != nil {
		return fmt.Errorf("failed to delete customer config: %w", err)
	}

	return nil
}

func (s *customerConfigService) IsMultipleItemsAllowed(ctx context.Context, customerID, pointOfSaleID string) (bool, error) {
	config, err := s.repo.GetByCustomerID(ctx, customerID, pointOfSaleID)
	if err != nil {
		return false, nil
	}

	return config.AllowMultipleItems, nil
}

func (s *customerConfigService) GetConfigsByPointOfSale(ctx context.Context, pointOfSaleID string) ([]domain.CustomerConfig, error) {
	configs, err := s.repo.GetByPointOfSaleID(ctx, pointOfSaleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get configs by point of sale: %w", err)
	}

	return configs, nil
}
