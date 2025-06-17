package services

import (
	"context"
)

type EmailServiceInterface interface {
	NotifyOffer(ctx context.Context, auctionURL string, offerName string, posId string) error
	NotifyOrder(ctx context.Context, state string, customerEmail string, totalOfferedAmount int64, concatenatedItemNames string) error
}

type EmailService struct {
	notifyOffer        *NotifyOfferUseCase
	notifyOrderUseCase *NotifyOrderUseCase
}

func NewEmailService(
	notifyOfferUC *NotifyOfferUseCase,
	notifyOrderUC *NotifyOrderUseCase,
) EmailServiceInterface {
	return &EmailService{
		notifyOffer:        notifyOfferUC,
		notifyOrderUseCase: notifyOrderUC,
	}
}

func (s *EmailService) NotifyOffer(ctx context.Context, auctionURL string, offerName string, posId string) error {
	return s.notifyOffer.Execute(ctx, auctionURL, offerName, posId)
}

func (s *EmailService) NotifyOrder(ctx context.Context, state string, customerEmail string, totalOfferedAmount int64, concatenatedItemNames string) error {
	return s.notifyOrderUseCase.Execute(
		state,
		customerEmail,
		concatenatedItemNames,
		totalOfferedAmount,
		"",
	)
}
