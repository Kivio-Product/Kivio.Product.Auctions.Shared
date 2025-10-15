package services

import (
	"context"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/repository"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

type NotifyOrderUseCase struct {
	notifier domain.Notifier
}

func NewNotifyOrderUseCase(notifier domain.Notifier) *NotifyOrderUseCase {
	return &NotifyOrderUseCase{
		notifier: notifier,
	}
}

func (uc *NotifyOrderUseCase) Execute(state string, customerEmail string, concatenatedItemNames string, firstOrderAmount int64, concatenatedItemDescriptions string, posName, orderStatusUrl string) error {
	templateName := getTemplateName(state) + posName
	p := message.NewPrinter(language.Spanish)
	formattedAmount := p.Sprintf("%d", firstOrderAmount)
	templateData := map[string]string{
		"ITEM_NAME":        concatenatedItemNames,
		"AMOUNT":           formattedAmount,
		"ITEM_DESCRIPTION": concatenatedItemDescriptions,
		"ORDER_STATUS_URL": orderStatusUrl,
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
	case "Pending":
		return "SubastaPendiente"
	case "Quick":
		return "CompraRapida"
	default:
		return "OfertaGeneral"
	}
}
