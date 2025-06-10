package services

import (
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

func (uc *NotifyOrderUseCase) Execute(state string, customerEmail string, itemName string, amount int64, itemDescription string) error {
	templateName := getTemplateName(state)
	templateData := map[string]string{
		"ITEM_NAME":        itemName,
		"AMOUNT":           strconv.FormatInt(amount, 10),
		"ITEM_DESCRIPTION": itemDescription,
	}

	return uc.notifier.SendTemplatedEmail(customerEmail, templateName, templateData)
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
