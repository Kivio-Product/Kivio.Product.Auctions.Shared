package services

import (
	"context"

	itemDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
	itemSpecDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item_specification"
	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
	infrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/email"
)

type EmailService interface {
	SendEmail(ctx context.Context, state string, order *domain.Order, itemSpec *itemSpecDomain.ItemSpecification, item *itemDomain.Item) error
}

type emailService struct {
	emailSender infrastructure.IEmailSender
}

func NewEmailService(emailSender infrastructure.IEmailSender) EmailService {
	return &emailService{emailSender: emailSender}
}

func (s *emailService) SendEmail(ctx context.Context, state string, order *domain.Order, itemSpec *itemSpecDomain.ItemSpecification, item *itemDomain.Item) error {
	return s.emailSender.SendOrderEmail(ctx, order, itemSpec, item, state)
}
