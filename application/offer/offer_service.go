package services

import (
	"context"
	"strconv"

	emailService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/email"
	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/offer"
	infrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/offer"
	"github.com/aws/aws-sdk-go/service/dynamodb"
)

type IOfferService interface {
	GenerateOffer(ctx context.Context, name, description, posId, typer string, auctionTime int64) (*domain.Offer, error)
	UpdateOffer(ctx context.Context, offerId, description, name string, auctionTime int64) error
	UpdateOfferState(ctx context.Context, offerId, state string) error
	GetOffers(ctx context.Context) ([]domain.Offer, error)
	GetOfferById(ctx context.Context, id string) (*domain.Offer, error)
	DeleteOfferById(ctx context.Context, id string) error
	GetOffersByPosId(ctx context.Context, id string, limit string, lastEvaluatedKey map[string]*dynamodb.AttributeValue) ([]domain.Offer, map[string]*dynamodb.AttributeValue, error)
	SendOfferEmail(ctx context.Context, auctionURL string, offerID string) error
}

type OfferService struct {
	repo         infrastructure.IOfferRepository
	emailSender  emailService.EmailServiceInterface
	offerFactory domain.OfferFactory
}

func NewofferService(repo infrastructure.IOfferRepository, offerFactory domain.OfferFactory, emailSender emailService.EmailServiceInterface) IOfferService {
	return &OfferService{
		repo:         repo,
		offerFactory: offerFactory,
		emailSender:  emailSender,
	}
}

func (s *OfferService) SendOfferEmail(ctx context.Context, auctionURL string, offerID string) error {
	offer, err := s.GetOfferById(ctx, offerID)
	if err != nil {
		return err
	}
	return s.emailSender.NotifyOffer(ctx, auctionURL, offer.Name)
}

func (s *OfferService) GenerateOffer(ctx context.Context, name, description, posId, typer string, auctionTime int64) (*domain.Offer, error) {
	offers, err := s.offerFactory.CreateOffer(name, description, posId, typer, auctionTime)
	if err != nil {
		return &domain.Offer{}, err
	}
	err = offers.UpdateState("Created")
	if err := s.repo.SaveOffer(ctx, offers); err != nil {
		return &domain.Offer{}, err
	}
	return offers, nil
}

func (s *OfferService) UpdateOffer(ctx context.Context, offerId, description, name string, auctionTime int64) error {
	offer, err := s.repo.GetOfferById(ctx, offerId)
	err = offer.Update(name, description, auctionTime)
	if err != nil {
		return err
	}
	return s.repo.SaveOffer(ctx, offer)
}

func (s *OfferService) UpdateOfferState(ctx context.Context, offerId, state string) error {
	offer, err := s.repo.GetOfferById(ctx, offerId)
	err = offer.UpdateState(state)
	if err != nil {
		return err
	}
	return s.repo.SaveOffer(ctx, offer)
}

func (s *OfferService) GetOffers(ctx context.Context) ([]domain.Offer, error) {
	offers, err := s.repo.GetAllOffers()
	if err != nil {
		return nil, err
	}
	return offers, nil
}

func (s *OfferService) GetOfferById(ctx context.Context, id string) (*domain.Offer, error) {
	items, err := s.repo.GetOfferById(ctx, id)
	if err != nil {
		return &domain.Offer{}, err
	}
	return items, nil
}

func (s *OfferService) DeleteOfferById(ctx context.Context, id string) error {
	err := s.repo.DeleteOffer(ctx, id)
	return err
}

func (s *OfferService) GetOffersByPosId(ctx context.Context, id string, limit string, lastEvaluatedKey map[string]*dynamodb.AttributeValue) ([]domain.Offer, map[string]*dynamodb.AttributeValue, error) {

	limitInt, err := strconv.Atoi(limit)
	if err != nil {
		return nil, nil, err
	}

	offers, lastKey, err := s.repo.GetPosOffers(id, limitInt, lastEvaluatedKey)
	if err != nil {
		return nil, nil, err
	}
	return offers, lastKey, nil
}
