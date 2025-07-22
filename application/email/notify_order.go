package services

import (
	"context"
	"strconv"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/repository"
)

type NotifyOrderUseCase struct {
	notifier domain.Notifier
}

func NewNotifyOrderUseCase(notifier domain.Notifier) *NotifyOrderUseCase {
	return &NotifyOrderUseCase{
		notifier: notifier,
	}
}

func (uc *NotifyOrderUseCase) Execute(state string, customerEmail string, concatenatedItemNames string, firstOrderAmount int64, concatenatedItemDescriptions string) error {
	templateName := getTemplateName(state)
	templateData := map[string]string{
		"ITEM_NAME":        concatenatedItemNames,
		"AMOUNT":           strconv.FormatInt(firstOrderAmount, 10),
		"ITEM_DESCRIPTION": concatenatedItemDescriptions,
	}

	return uc.notifier.SendTemplatedEmail(customerEmail, templateName, templateData)
}

type NotifyAdminApprovedOrdersUseCase struct {
	notifier domain.Notifier
}

func NewNotifyAdminApprovedOrdersUseCase(notifier domain.Notifier) *NotifyAdminApprovedOrdersUseCase {
	return &NotifyAdminApprovedOrdersUseCase{
		notifier: notifier,
	}
}

func (uc *NotifyAdminApprovedOrdersUseCase) Execute(ctx context.Context, adminEmail string, templateData map[string]string) error {
	return uc.notifier.SendTemplatedEmail(adminEmail, "AdminApprovedOrders", templateData)
}

func (uc *NotifyAdminApprovedOrdersUseCase) ExecuteWithAttachment(ctx context.Context, adminEmail string, subject string, body string, attachmentName string, attachmentData []byte) error {
	return uc.notifier.SendEmailWithAttachment(adminEmail, subject, body, attachmentName, attachmentData)
}

func getTemplateName(state string) string {
	switch state {
	case "Approved":
		return "SubastaAprobada"
	case "Rejected":
		return "SubastaRechazada"
	case "Quick":
		return "CompraRapida"
	default:
		return "OfertaGeneral"
	}
}
