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

func NewEmailService(emailSource infrastructure.EmailSourceStrategy, ecommerceSource infrastructure.EcommerceEmailSourceStrategy) (EmailService, error) {
	emailSender, err := infrastructure.NewSESEmailSender(emailSource, ecommerceSource)
	if err != nil {
		return nil, err
	}
	return &emailService{emailSender: emailSender}, nil
}

func (s *emailService) SendEmail(ctx context.Context, state string, order *domain.Order, itemSpec *itemSpecDomain.ItemSpecification, item *itemDomain.Item) error {
	return s.emailSender.SendOrderEmail(ctx, order, itemSpec, item, state)
}
