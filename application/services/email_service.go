package services

import (
	"context"

	"github.com/Kivio-Product/Kivio.Product.Auctions.Services/internal/domain"
	"github.com/Kivio-Product/Kivio.Product.Auctions.Services/internal/infrastructure"
)

type EmailService interface {
	SendEmail(ctx context.Context, state string, order *domain.Order, itemSpec *domain.ItemSpecification, item *domain.Item) error
}

type emailService struct {
	emailSender infrastructure.IEmailSender
}

func NewEmailService(emailSender infrastructure.IEmailSender) EmailService {
	return &emailService{emailSender: emailSender}
}

func (s *emailService) SendEmail(ctx context.Context, state string, order *domain.Order, itemSpec *domain.ItemSpecification, item *domain.Item) error {
	return s.emailSender.SendEmail(ctx, order, itemSpec, item, state)
}
