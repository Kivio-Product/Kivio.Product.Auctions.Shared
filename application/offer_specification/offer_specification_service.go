package services

import (
	"context"

	offer "github.com/Kivio-Product/Kivio.Product.Auctions.Domain.Shared/offer"
	"github.com/Kivio-Product/Kivio.Product.Auctions.Offers/internal/infrastructure"
)

type IOfferSpecificationService interface {
	GenerateOfferSpecification(ctx context.Context, externalID, offerID string) (*offer.OfferSpecification, error)
}

type OfferSpecificationService struct {
	repo                      infrastructure.IOfferSpecificationRepository
	offerSpecificationFactory offer.OfferSpecificationFactory
}

func NewofferSpecificationService(repo infrastructure.IOfferSpecificationRepository, offerSpecificationFactory offer.OfferSpecificationFactory) IOfferSpecificationService {
	return &OfferSpecificationService{repo: repo, offerSpecificationFactory: offerSpecificationFactory}
}

func (s *OfferSpecificationService) GenerateOfferSpecification(ctx context.Context, externalID, offerID string) (*offer.OfferSpecification, error) {
	specification, err := s.offerSpecificationFactory.CreateOfferSpecification(externalID, offerID)
	if err != nil {
		return &offer.OfferSpecification{}, err
	}
	if err := s.repo.SaveOfferSpecification(ctx, specification); err != nil {
		return &offer.OfferSpecification{}, err
	}
	return specification, nil
}
