package services

import (
	"context"

	itemDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
	itemSpecDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item_specification"
	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
)

type EmailServiceInterface interface {
	NotifyOffer(ctx context.Context, auctionURL string, offerName string) error
	NotifyOrder(ctx context.Context, state string, order *domain.Order, itemSpec *itemSpecDomain.ItemSpecification, item *itemDomain.Item) error
}

type EmailService struct {
	notifyOffer        *NotifyOfferUseCase
	notifyOrderUseCase *NotifyOrderUseCase
}

func NewEmailService(
	notifyOfferUC *NotifyOfferUseCase,
	notifyOrderUC *NotifyOrderUseCase,
) *EmailService {
	return &EmailService{
		notifyOffer:        notifyOfferUC,
		notifyOrderUseCase: notifyOrderUC,
	}
}

func (s *EmailService) NotifyOffer(ctx context.Context, auctionURL string, offerName string) error {
	return s.notifyOffer.Execute(ctx, auctionURL, offerName)
}

func (s *EmailService) NotifyOrder(ctx context.Context, state string, order *domain.Order, itemSpec *itemSpecDomain.ItemSpecification, item *itemDomain.Item) error {
	return s.notifyOrderUseCase.Execute(
		state,
		order.CustomerId,
		item.Name,
		order.OfferedAmount,
		item.Description,
	)
}
