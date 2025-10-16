package helpers

import (
	"context"
	"fmt"
	"strings"

	emailService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/email"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
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

func (h *NotificationHelper) SendOrderNotificationGroupedByState(
	ctx context.Context,
	orders []*orderDomain.Order,
	posName string,
) {
	if len(orders) == 0 {
		return
	}

	ordersByCustomer := make(map[string][]*orderDomain.Order)
	for _, order := range orders {
		ordersByCustomer[order.CustomerId] = append(ordersByCustomer[order.CustomerId], order)
	}

	fmt.Printf("[NotificationHelper] Sending notifications for %d customers\n", len(ordersByCustomer))

	for customerID, customerOrders := range ordersByCustomer {
		approvedOrders := []*orderDomain.Order{}
		rejectedOrders := []*orderDomain.Order{}

		for _, order := range customerOrders {
			if order.State == "Approved" {
				approvedOrders = append(approvedOrders, order)
			} else if order.State == "Rejected" {
				rejectedOrders = append(rejectedOrders, order)
			}
		}

		fmt.Printf("[NotificationHelper] Customer %s - Approved: %d, Rejected: %d\n",
			customerID, len(approvedOrders), len(rejectedOrders))

		if len(approvedOrders) > 0 {
			h.sendNotificationForOrders(ctx, customerID, approvedOrders, "Approved", posName)
		}

		if len(rejectedOrders) > 0 {
			h.sendNotificationForOrders(ctx, customerID, rejectedOrders, "Rejected", posName)
		}
	}
}

func (h *NotificationHelper) sendNotificationForOrders(
	ctx context.Context,
	customerEmail string,
	orders []*orderDomain.Order,
	state string,
	posName string,
) {
	if len(orders) == 0 {
		return
	}

	var itemNames []string
	var totalAmount int64

	for _, order := range orders {
		itemNames = append(itemNames, order.ExtraData)
		totalAmount += int64(order.OfferedAmount)
	}

	fmt.Printf("[NotificationHelper] Sending %s notification to %s for %d items (total: %d)\n",
		state, customerEmail, len(itemNames), totalAmount)

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
			fmt.Printf("No se pudo enviar el correo de estado %s a %s: %s\n", state, customerEmail, err)
		} else {
			fmt.Printf("Correo de estado %s enviado exitosamente a %s\n", state, customerEmail)
		}
	}()
}
