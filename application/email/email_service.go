package services

import (
	"context"
)

type EmailServiceInterface interface {
	NotifyOffer(ctx context.Context, auctionURL, unsubscribeUrl string, offerName string, posId string, posName string) error
	NotifyOrder(ctx context.Context, state string, customerEmail string, totalOfferedAmount int64, concatenatedItemNames string, posName string) error
	NotifyOrderStatus(ctx context.Context, customerId string, status string, itemNames string, offeredAmount int64, posId string) error
	NotifyAdminApprovedOrders(ctx context.Context, adminEmail string, templateData map[string]string) error
	NotifyAdminApprovedOrdersWithAttachment(ctx context.Context, adminEmail string, subject string, body string, attachmentName string, attachmentData []byte) error
}

type EmailService struct {
	notifyOffer                      *NotifyOfferUseCase
	notifyOrderUseCase               *NotifyOrderUseCase
	NotifyAdminApprovedOrdersUseCase *NotifyAdminApprovedOrdersUseCase
}

func NewEmailService(
	notifyOfferUC *NotifyOfferUseCase,
	notifyOrderUC *NotifyOrderUseCase,
	NotifyAdminApprovedOrdersUC *NotifyAdminApprovedOrdersUseCase,
) EmailServiceInterface {
	return &EmailService{
		notifyOffer:                      notifyOfferUC,
		notifyOrderUseCase:               notifyOrderUC,
		NotifyAdminApprovedOrdersUseCase: NotifyAdminApprovedOrdersUC,
	}
}

func (s *EmailService) NotifyOffer(ctx context.Context, auctionURL, unsubscribeUrl string, offerName string, posId string, posName string) error {
	return s.notifyOffer.Execute(ctx, auctionURL, unsubscribeUrl, offerName, posId, posName)
}

func (s *EmailService) NotifyOrder(ctx context.Context, state string, customerEmail string, totalOfferedAmount int64, concatenatedItemNames string, posName string) error {
	return s.notifyOrderUseCase.Execute(
		state,
		customerEmail,
		concatenatedItemNames,
		totalOfferedAmount,
		"",
		posName,
	)
}

func (s *EmailService) NotifyAdminApprovedOrders(ctx context.Context, adminEmail string, templateData map[string]string) error {
	return s.NotifyAdminApprovedOrdersUseCase.Execute(ctx, adminEmail, templateData)
}

func (s *EmailService) NotifyOrderStatus(ctx context.Context, customerId string, status string, itemNames string, offeredAmount int64, posId string) error {
	return s.notifyOrderUseCase.Execute(
		status,
		customerId,
		itemNames,
		offeredAmount,
		"",
		posId,
	)
}

func (s *EmailService) NotifyAdminApprovedOrdersWithAttachment(ctx context.Context, adminEmail string, subject string, body string, attachmentName string, attachmentData []byte) error {
	return s.NotifyAdminApprovedOrdersUseCase.ExecuteWithAttachment(ctx, adminEmail, subject, body, attachmentName, attachmentData)
}
