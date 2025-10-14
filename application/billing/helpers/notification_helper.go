package helpers

import (
	"context"
	"fmt"
	"strings"

	emailService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/email"
)

type NotificationHelper struct {
	emailService emailService.EmailServiceInterface
}

func NewNotificationHelper(emailService emailService.EmailServiceInterface) *NotificationHelper {
	return &NotificationHelper{
		emailService: emailService,
	}
}

func (h *NotificationHelper) SendOrderNotification(
	ctx context.Context,
	state string,
	customerEmail string,
	totalAmount int64,
	itemNames []string,
	posName string,
) {
	if customerEmail == "" || len(itemNames) == 0 {
		return
	}

	go func() {
		err := h.emailService.NotifyOrder(
			ctx,
			state,
			customerEmail,
			totalAmount,
			strings.Join(itemNames, ", "),
			posName,
			"",
		)
		if err != nil {
			fmt.Printf("No se pudo enviar el correo: %s\n", err)
		}
	}()
}
