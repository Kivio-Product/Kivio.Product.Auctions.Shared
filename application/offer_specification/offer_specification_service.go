package services

import (
	"context"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/offer_specification"
	infrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/offer_specification"
)

type IOfferSpecificationService interface {
	GenerateOfferSpecification(ctx context.Context, externalID, offerID string) (*domain.OfferSpecification, error)
}

type OfferSpecificationService struct {
	repo                      infrastructure.IOfferSpecificationRepository
	offerSpecificationFactory domain.OfferSpecificationFactory
}

// NewofferSpecificationService creates a new instance of OfferSpecificationService with required dependencies
func NewofferSpecificationService(repo infrastructure.IOfferSpecificationRepository, offerSpecificationFactory domain.OfferSpecificationFactory) IOfferSpecificationService {
	return &OfferSpecificationService{repo: repo, offerSpecificationFactory: offerSpecificationFactory}
}

// GenerateOfferSpecification creates a new offer specification and saves it to the repository
func (s *OfferSpecificationService) GenerateOfferSpecification(ctx context.Context, externalID, offerID string) (*domain.OfferSpecification, error) {
	specification, err := s.offerSpecificationFactory.CreateOfferSpecification(externalID, offerID)
	if err != nil {
		return &domain.OfferSpecification{}, err
	}
	if err := s.repo.SaveOfferSpecification(ctx, specification); err != nil {
		return &domain.OfferSpecification{}, err
	}
	return specification, nil
}
