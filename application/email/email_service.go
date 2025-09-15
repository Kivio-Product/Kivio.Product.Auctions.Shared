package services

import (
	"context"
	"time"

	applicationLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/logging"
	domainLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/logging"
	infrastructureLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/logging"
)

type EmailServiceInterface interface {
	NotifyOffer(ctx context.Context, auctionURL string, offerName string, posId string, posName string) error
	NotifyOrder(ctx context.Context, state string, customerEmail string, totalOfferedAmount int64, concatenatedItemNames string, posName string) error
	NotifyOrderStatus(ctx context.Context, customerId string, status string, itemNames string, offeredAmount int64, posId string) error
	NotifyAdminApprovedOrders(ctx context.Context, adminEmail string, templateData map[string]string) error
	NotifyAdminApprovedOrdersWithAttachment(ctx context.Context, adminEmail string, subject string, body string, attachmentName string, attachmentData []byte) error
}

type EmailService struct {
	notifyOffer                      *NotifyOfferUseCase
	notifyOrderUseCase               *NotifyOrderUseCase
	NotifyAdminApprovedOrdersUseCase *NotifyAdminApprovedOrdersUseCase
	logger                           applicationLogging.ServiceLogger
}

func NewEmailService(
	notifyOfferUC *NotifyOfferUseCase,
	notifyOrderUC *NotifyOrderUseCase,
	NotifyAdminApprovedOrdersUC *NotifyAdminApprovedOrdersUseCase,
) EmailServiceInterface {
	loggerRepo := infrastructureLogging.GetLoggerRepository()
	return &EmailService{
		notifyOffer:                      notifyOfferUC,
		notifyOrderUseCase:               notifyOrderUC,
		NotifyAdminApprovedOrdersUseCase: NotifyAdminApprovedOrdersUC,
		logger:                           applicationLogging.NewServiceLogger(loggerRepo, "EmailService"),
	}
}

func (s *EmailService) NotifyOffer(ctx context.Context, auctionURL string, offerName string, posId string, posName string) error {
	start := time.Now()
	
	logFields := domainLogging.Fields{
		"offer_name": offerName,
		"pos_id":     posId,
		"pos_name":   posName,
		"email_type": "offer_notification",
	}
	
	s.logger.LogServiceStart(ctx, "EmailService", "NotifyOffer", logFields)
	
	err := s.notifyOffer.Execute(ctx, auctionURL, offerName, posId, posName)
	duration := time.Since(start)
	
	if err != nil {
		s.logger.LogServiceError(ctx, "EmailService", "NotifyOffer", err, duration, logFields)
		return err
	}
	
	s.logger.LogServiceSuccess(ctx, "EmailService", "NotifyOffer", duration, logFields)
	s.logger.LogBusinessEvent(ctx, "email_sent", logFields)
	
	return nil
}

func (s *EmailService) NotifyOrder(ctx context.Context, state string, customerEmail string, totalOfferedAmount int64, concatenatedItemNames string, posName string) error {
	start := time.Now()
	
	logFields := domainLogging.Fields{
		"customer_email":      customerEmail,
		"order_state":         state,
		"total_amount":        totalOfferedAmount,
		"pos_name":           posName,
		"email_type":         "order_notification",
	}
	
	s.logger.LogServiceStart(ctx, "EmailService", "NotifyOrder", logFields)
	
	err := s.notifyOrderUseCase.Execute(
		state,
		customerEmail,
		concatenatedItemNames,
		totalOfferedAmount,
		"",
		posName,
	)
	duration := time.Since(start)
	
	if err != nil {
		s.logger.LogServiceError(ctx, "EmailService", "NotifyOrder", err, duration, logFields)
		return err
	}
	
	s.logger.LogServiceSuccess(ctx, "EmailService", "NotifyOrder", duration, logFields)
	s.logger.LogBusinessEvent(ctx, "email_sent", logFields)
	
	return nil
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
