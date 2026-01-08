package payment_confirmation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	billingHelpers "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/billing/helpers"
	offerService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/offer"
	offerDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/offer"
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

	if state == "Approved" {
		fmt.Printf("[SendEventAnalytics] Data from event offerId from result: %s\n", result.OfferID)
		offer, err := o.offerService.GetOfferById(ctx, result.OfferID)
		if err != nil {
			fmt.Printf("Error al obtener la oferta con ID %d: %v\n", result.OfferID, err)
		}

		if offer != nil && offer.OfferId != "" {
			o.sendEventAnalytics(offer, billing.UserId, billing.GaClienId, result.TotalAmount)
		}
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

func (o *PaymentConfirmationOrchestrator) sendEventAnalytics(offer *offerDomain.Offer, userId string, gaClientId *string, totalAmount int64) {
	fmt.Printf("[SendEventAnalytics] Start event to analytics")
	fmt.Printf("[SendEventAnalytics] Data from event offerName: %s, userId: %s, totalAmount:%d\n", offer.Name, userId, totalAmount)

	if gaClientId != nil {
		fmt.Printf("[SendEventAnalytics] Data from event gaClientId: %s\n", *gaClientId)
	} 
	var (
		measurementID = os.Getenv("GA_MEASUREMENT_ID")
		apiSecret     = os.Getenv("GA_API_SECRET")
	)

	type GAEvent struct {
		Name   string                 `json:"name"`
		Params map[string]interface{} `json:"params,omitempty"`
	}

	type GAPayload struct {
		UserID   string    `json:"user_id"`
		ClientID string    `json:"client_id"`
		Events   []GAEvent `json:"events"`
	}

	payload := GAPayload{
		ClientID: *gaClientId,
		UserID: userId,
		Events: []GAEvent{
			{
				Name: "payment_confirm",
				Params: map[string]interface{}{
					"value":      totalAmount,
					"offer_id":   offer.OfferId,
					"offer_type": offer.Type,
					"offer_name": offer.Name,
					"debug_mode": true,
				},
			},
		},
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}

	url := fmt.Sprintf(
		"https://www.google-analytics.com/mp/collect?measurement_id=%s&api_secret=%s",
		measurementID, apiSecret,
	)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	fmt.Println("Status Code:", resp.StatusCode)
	if resp.StatusCode == 204 {
		fmt.Println("Evento enviado correctamente a GA4")
	} else {
		fmt.Printf("Error al enviar evento a Analytics: %v\n", err)
	}
}
