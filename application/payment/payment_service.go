package services

import (
	"context"
	"fmt"
	"os"

	billingService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/billing"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
	paymentDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/payment"
)

type PaymentService interface {
	ProcessPaymentForCustomer(ctx context.Context, orders []*orderDomain.Order) error
}

type paymentService struct {
	wompiService   WompiService
	billingService billingService.BillingService
}

func NewPaymentService(
	wompiService WompiService,
	billingService billingService.BillingService,
) PaymentService {
	return &paymentService{
		wompiService:   wompiService,
		billingService: billingService,
	}
}

func (s *paymentService) ProcessPaymentForCustomer(ctx context.Context, orders []*orderDomain.Order) error {
	if len(orders) == 0 {
		return fmt.Errorf("no orders provided for payment processing")
	}

	customerId := orders[0].CustomerId
	for _, order := range orders {
		if order.CustomerId != customerId {
			return fmt.Errorf("all orders must belong to the same customer")
		}
		if order.WompiIdPayment == "" {
			return fmt.Errorf("order %s does not have WompiIdPayment", order.OrderId)
		}
	}

	billingReference, err := s.billingService.GetBillingReferenceByOrderId(ctx, orders[0].OrderId)
	if err != nil {
		return fmt.Errorf("error getting billing reference: %w", err)
	}

	var totalAmount int64
	for _, order := range orders {
		amountInCents := order.OfferedAmount
		if amountInCents < 1000000 {
			amountInCents = int64(float64(order.OfferedAmount) * 100)
		}
		totalAmount += amountInCents
	}

	wompiReq := &paymentDomain.WompiTransactionRequest{
		AmountInCents:   totalAmount,
		Currency:        "COP",
		CustomerEmail:   customerId,
		PaymentSourceId: 0,
		Reference:       billingReference,
		PaymentMethod: &paymentDomain.WompiPaymentMethod{
			Installments: 1,
		},
	}

	var paymentSourceId int64
	_, err = fmt.Sscan(orders[0].WompiIdPayment, &paymentSourceId)
	if err != nil {
		return fmt.Errorf("error converting WompiIdPayment to int64: %w", err)
	}
	wompiReq.PaymentSourceId = paymentSourceId

	integritySecret := os.Getenv("WOMPI_INTEGRITY_SECRET")
	if integritySecret == "" {
		return fmt.Errorf("WOMPI_INTEGRITY_SECRET not configured")
	}

	signatureResp, err := s.wompiService.GenerateIntegritySignature(ctx, billingReference, totalAmount, "COP", integritySecret, nil)
	if err != nil {
		return fmt.Errorf("error generating Wompi signature: %w", err)
	}
	wompiReq.Signature = signatureResp.Signature

	_, err = s.wompiService.CreateTransaction(ctx, wompiReq)
	if err != nil {
		return fmt.Errorf("error creating Wompi transaction for customer %s with total amount %d: %w", customerId, totalAmount, err)
	}

	return nil
}
