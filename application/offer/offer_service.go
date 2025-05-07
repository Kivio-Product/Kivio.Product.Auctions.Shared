package services

import (
	"context"
	"strconv"

	offer "github.com/Kivio-Product/Kivio.Product.Auctions.Domain.Shared/offer"
	sharedinfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Infrastructure.Shared"
	"github.com/Kivio-Product/Kivio.Product.Auctions.Offers/internal/infrastructure"
	"github.com/aws/aws-sdk-go/service/dynamodb"
)

type IOfferService interface {
	GenerateOffer(ctx context.Context, name, description, posId, typer string, auctionTime int64) (*offer.Offer, error)
	UpdateOffer(ctx context.Context, offerId, description, name string, auctionTime int64) error
	UpdateOfferState(ctx context.Context, offerId, state string) error
	GetOffers(ctx context.Context) ([]offer.Offer, error)
	GetOfferById(ctx context.Context, id string) (*offer.Offer, error)
	DeleteOfferById(ctx context.Context, id string) error
	GetOffersByPosId(ctx context.Context, id string, limit string, lastEvaluatedKey map[string]*dynamodb.AttributeValue) ([]offer.Offer, map[string]*dynamodb.AttributeValue, error)
	SendOfferEmail(ctx context.Context, auctionURL string, offerID string) error
}

type OfferService struct {
	repo         infrastructure.IOfferRepository
	emailSender  sharedinfrastructure.IEmailSender
	offerFactory offer.OfferFactory
}

func NewofferService(repo infrastructure.IOfferRepository, offerFactory offer.OfferFactory, emailSender sharedinfrastructure.IEmailSender) IOfferService {
	return &OfferService{
		repo:         repo,
		offerFactory: offerFactory,
		emailSender:  emailSender,
	}
}

func (s *OfferService) SendOfferEmail(ctx context.Context, auctionURL string, offerID string) error {
	offer, err := s.repo.GetOfferById(ctx, offerID)
	if err != nil {
		return err
	}

	return s.emailSender.SendEmail(ctx, offer, auctionURL)
}

func (s *OfferService) GenerateOffer(ctx context.Context, name, description, posId, typer string, auctionTime int64) (*offer.Offer, error) {
	offers, err := s.offerFactory.CreateOffer(name, description, posId, typer, auctionTime)
	if err != nil {
		return &offer.Offer{}, err
	}
	err = offers.UpdateState("Created")
	if err := s.repo.SaveOffer(ctx, offers); err != nil {
		return &offer.Offer{}, err
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

func (s *OfferService) GetOffers(ctx context.Context) ([]offer.Offer, error) {
	offers, err := s.repo.GetAllOffers()
	if err != nil {
		return nil, err
	}
	return offers, nil
}

func (s *OfferService) GetOfferById(ctx context.Context, id string) (*offer.Offer, error) {
	items, err := s.repo.GetOfferById(ctx, id)
	if err != nil {
		return &offer.Offer{}, err
	}
	return items, nil
}

func (s *OfferService) DeleteOfferById(ctx context.Context, id string) error {
	err := s.repo.DeleteOffer(ctx, id)
	return err
}

func (s *OfferService) GetOffersByPosId(ctx context.Context, id string, limit string, lastEvaluatedKey map[string]*dynamodb.AttributeValue) ([]offer.Offer, map[string]*dynamodb.AttributeValue, error) {

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
