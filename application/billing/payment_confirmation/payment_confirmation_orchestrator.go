package payment_confirmation

import (
	"context"
	"fmt"

	billingHelpers "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/billing/helpers"
	offerService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/offer"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
	domainStrategy "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/strategy"
)

type PaymentConfirmationOrchestrator struct {
	billingHelper          *billingHelpers.BillingHelper
	orderHelper            *billingHelpers.OrderHelper
	notificationHelper     *billingHelpers.NotificationHelper
	offerService           offerService.IOfferService
	quickOfferStrategy     domainStrategy.OfferProcessingStrategy
	regularAuctionStrategy domainStrategy.OfferProcessingStrategy
}

func NewPaymentConfirmationOrchestrator(
	billingHelper *billingHelpers.BillingHelper,
	orderHelper *billingHelpers.OrderHelper,
	notificationHelper *billingHelpers.NotificationHelper,
	offerService offerService.IOfferService,
	quickOfferStrategy domainStrategy.OfferProcessingStrategy,
	regularAuctionStrategy domainStrategy.OfferProcessingStrategy,
) *PaymentConfirmationOrchestrator {
	return &PaymentConfirmationOrchestrator{
		billingHelper:          billingHelper,
		orderHelper:            orderHelper,
		notificationHelper:     notificationHelper,
		offerService:           offerService,
		quickOfferStrategy:     quickOfferStrategy,
		regularAuctionStrategy: regularAuctionStrategy,
	}
}

func (o *PaymentConfirmationOrchestrator) ExecutePaymentConfirmation(
	ctx context.Context,
	billingID string,
	state string,
	paymentMethod string,
	transactionID string,
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

	offerProcessingStrategy := o.getStrategyForOrders(ctx, validOrders)
	fmt.Printf("[PaymentConfirmation] Using strategy: %s\n", offerProcessingStrategy.GetOfferType())

	result, err := offerProcessingStrategy.ProcessApprovedOrders(ctx, validOrders, billing, state)
	if err != nil {
		return fmt.Errorf("error processing orders with %s strategy: %w", offerProcessingStrategy.GetOfferType(), err)
	}

	fmt.Printf("[PaymentConfirmation] Processed %d orders with strategy: %s\n", result.ProcessedOrders, offerProcessingStrategy.GetOfferType())

	o.notificationHelper.SendOrderNotificationGroupedByState(
		ctx,
		validOrders,
		posName,
		state,
	)

	fmt.Println("Facturación actualizada correctamente")
	return nil
}

func (o *PaymentConfirmationOrchestrator) getStrategyForOrders(ctx context.Context, orders []*orderDomain.Order) domainStrategy.OfferProcessingStrategy {
	if len(orders) == 0 {
		fmt.Printf("[PaymentConfirmation] No orders found - using Quick Offer strategy as default\n")
		return o.quickOfferStrategy
	}

	offerID := orders[0].OfferId
	if offerID == "" {
		fmt.Printf("[PaymentConfirmation] No OfferId found - using Quick Offer strategy\n")
		return o.quickOfferStrategy
	}

	offer, err := o.offerService.GetOfferById(ctx, offerID)
	if err != nil {
		fmt.Printf("[PaymentConfirmation] Error getting offer %s: %v - using Quick Offer strategy\n", offerID, err)
		return o.quickOfferStrategy
	}

	if offer.Type == "Regular auction" {
		fmt.Printf("[PaymentConfirmation] Offer %s is Regular Auction - using Regular Auction strategy\n", offerID)
		return o.regularAuctionStrategy
	}

	fmt.Printf("[PaymentConfirmation] Offer %s is %s - using Quick Offer strategy\n", offerID, offer.Type)
	return o.quickOfferStrategy
}
