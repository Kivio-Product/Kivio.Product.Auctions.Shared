package services

import (
	"context"
	"fmt"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/customer"
)

type CustomerService interface {
	GetOrCreateCustomer(ctx context.Context, email string) (*domain.Customer, error)
	UpdateExternalCustomerID(ctx context.Context, email, externalCustomerID string) error
}

type customerService struct {
	repo domain.CustomerRepository
}

func NewCustomerService(repo domain.CustomerRepository) CustomerService {
	return &customerService{
		repo: repo,
	}
}

func (s *customerService) GetOrCreateCustomer(ctx context.Context, email string) (*domain.Customer, error) {
	existingCustomer, err := s.repo.GetByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("error checking existing customer: %v", err)
	}

	if existingCustomer != nil {
		return existingCustomer, nil
	}

	newCustomer := &domain.Customer{
		Email: email,
	}

	err = s.repo.Create(ctx, newCustomer)
	if err != nil {
		return nil, fmt.Errorf("error creating new customer: %v", err)
	}

	return newCustomer, nil
}

func (s *customerService) UpdateExternalCustomerID(ctx context.Context, email, externalCustomerID string) error {
	customer, err := s.repo.GetByEmail(ctx, email)
	if err != nil {
		return fmt.Errorf("error getting customer: %v", err)
	}

	if customer == nil {
		return fmt.Errorf("customer not found")
	}

	customer.ExternalCustomerID = externalCustomerID

	err = s.repo.Update(ctx, customer)
	if err != nil {
		return fmt.Errorf("error updating customer external ID: %v", err)
	}

	return nil
}
