package payment_confirmation

import (
	"context"
	"fmt"

	"time"

	billingHelpers "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/billing/helpers"
	invoiceService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/invoice"
	billingDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/billing"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
	domainStrategy "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/strategy"
)

// PaymentConfirmationOrchestrator coordina el flujo completo de confirmación de pago
type PaymentConfirmationOrchestrator struct {
	billingHelper      *billingHelpers.BillingHelper
	orderHelper        *billingHelpers.OrderHelper
	notificationHelper *billingHelpers.NotificationHelper
	invoiceService     invoiceService.InvoiceService
}

func NewPaymentConfirmationOrchestrator(
	billingHelper *billingHelpers.BillingHelper,
	orderHelper *billingHelpers.OrderHelper,
	notificationHelper *billingHelpers.NotificationHelper,
	invoiceService invoiceService.InvoiceService,
) *PaymentConfirmationOrchestrator {
	return &PaymentConfirmationOrchestrator{
		billingHelper:      billingHelper,
		orderHelper:        orderHelper,
		notificationHelper: notificationHelper,
		invoiceService:     invoiceService,
	}
}

func (o *PaymentConfirmationOrchestrator) ExecutePaymentConfirmation(
	ctx context.Context,
	billingID string,
	state string,
	paymentMethod string,
	transactionID string,
	offerProcessingStrategy domainStrategy.OfferProcessingStrategy,
) error {

	billing, err := o.billingHelper.GetAndValidateBilling(ctx, billingID)
	if err != nil {
		return err
	}

	err = o.billingHelper.UpdateBillingState(ctx, billing, state, paymentMethod, transactionID)
	if err != nil {
		return err
	}

	validOrders, err := o.orderHelper.GetValidOrdersByBillingID(ctx, billingID)
	if err != nil {
		return err
	}

	posID, posName := o.orderHelper.GetPOSName(ctx, validOrders)
	fmt.Printf("Processing orders for POS: %s (%s)\n", posID, posName)

	result, err := offerProcessingStrategy.ProcessApprovedOrders(ctx, validOrders, billing, state)
	if err != nil {
		return fmt.Errorf("error processing orders with %s strategy: %w", offerProcessingStrategy.GetOfferType(), err)
	}

	fmt.Printf("[PaymentConfirmation] Processed %d orders with strategy: %s\n", result.ProcessedOrders, offerProcessingStrategy.GetOfferType())

	o.notificationHelper.SendOrderNotification(
		ctx,
		state,
		result.CustomerEmail,
		result.TotalAmount,
		result.ItemNames,
		posName,
	)

	if state == "Approved" && len(validOrders) > 0 {
		go o.createInvoiceForApprovedPayment(ctx, billingID, validOrders, posName, billing)
	}

	fmt.Println("Facturación actualizada correctamente")
	return nil
}

func (o *PaymentConfirmationOrchestrator) createInvoiceForApprovedPayment(
	ctx context.Context,
	billingID string,
	orders []*orderDomain.Order,
	posName string,
	billing *billingDomain.Billing,
) {
	if len(orders) == 0 {
		fmt.Printf("No orders provided for invoice creation for billing %s\n", billingID)
		return
	}

	if billing.Customer == nil || billing.InvoiceConfig == nil {
		fmt.Printf("Missing customer or invoice config for billing %s\n", billingID)
		return
	}

	invoiceCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	fmt.Printf("DEBUG: Creating invoice with new context for billing %s\n", billingID)

	_, err := o.invoiceService.CreateInvoiceForOrders(invoiceCtx, billingID, orders, billing.Customer, billing.InvoiceConfig, posName)
	if err != nil {
		fmt.Printf("Error creating invoice for billing %s: %v\n", billingID, err)
		return
	}

	fmt.Printf("Invoice created successfully for billing %s with %d orders\n", billingID, len(orders))
}
