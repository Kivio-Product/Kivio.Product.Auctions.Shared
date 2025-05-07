package services

import (
	"context"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/offer_specification"
	infrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/offer_specification"
)

type IOfferSpecificationService interface {
	GenerateOfferSpecification(ctx context.Context, externalID, offerID string) (*domain.OfferSpecification, error)
}

type OfferSpecificationService struct {
	repo                      infrastructure.IOfferSpecificationRepository
	offerSpecificationFactory domain.OfferSpecificationFactory
}

func NewofferSpecificationService(repo infrastructure.IOfferSpecificationRepository, offerSpecificationFactory domain.OfferSpecificationFactory) IOfferSpecificationService {
	return &OfferSpecificationService{repo: repo, offerSpecificationFactory: offerSpecificationFactory}
}

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
