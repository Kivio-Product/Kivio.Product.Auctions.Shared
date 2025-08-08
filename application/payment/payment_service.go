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
	ProcessPaymentForOrder(ctx context.Context, order *orderDomain.Order) error
	CanProcessPaymentForCustomer(ctx context.Context, customerId string) (bool, error)
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

func (s *paymentService) CanProcessPaymentForCustomer(ctx context.Context, customerId string) (bool, error) {
	billings, err := s.billingService.GetAllBillings(ctx)
	if err != nil {
		return false, fmt.Errorf("error checking existing payments for customer: %w", err)
	}

	for _, billing := range billings {
		if billing.CustomerId != nil && *billing.CustomerId == customerId && billing.State == "Approved" {
			return false, nil
		}
	}

	return true, nil
}

func (s *paymentService) ProcessPaymentForOrder(ctx context.Context, order *orderDomain.Order) error {
	if order.WompiIdPayment == "" {
		return fmt.Errorf("order %s does not have WompiIdPayment", order.OrderId)
	}

	canProcess, err := s.CanProcessPaymentForCustomer(ctx, order.CustomerId)
	if err != nil {
		return fmt.Errorf("error checking payment eligibility for customer %s: %w", order.CustomerId, err)
	}

	if !canProcess {
		return fmt.Errorf("customer %s already has an approved payment", order.CustomerId)
	}

	billingReference, err := s.billingService.GetBillingReferenceByOrderId(ctx, order.OrderId)
	if err != nil {
		return fmt.Errorf("error getting billing reference: %w", err)
	}

	amountInCents := order.OfferedAmount
	if amountInCents < 1000000 {
		amountInCents = int64(float64(order.OfferedAmount) * 100)
	}

	wompiReq := &paymentDomain.WompiTransactionRequest{
		AmountInCents:   amountInCents,
		Currency:        "COP",
		CustomerEmail:   order.CustomerId,
		PaymentSourceId: 0,
		Reference:       billingReference,
		PaymentMethod: &paymentDomain.WompiPaymentMethod{
			Installments: 1,
		},
	}

	var paymentSourceId int64
	_, err = fmt.Sscan(order.WompiIdPayment, &paymentSourceId)
	if err != nil {
		return fmt.Errorf("error converting WompiIdPayment to int64: %w", err)
	}
	wompiReq.PaymentSourceId = paymentSourceId

	integritySecret := os.Getenv("WOMPI_INTEGRITY_SECRET")
	if integritySecret == "" {
		return fmt.Errorf("WOMPI_INTEGRITY_SECRET not configured")
	}

	signatureResp, err := s.wompiService.GenerateIntegritySignature(ctx, billingReference, amountInCents, "COP", integritySecret, nil)
	if err != nil {
		return fmt.Errorf("error generating Wompi signature: %w", err)
	}
	wompiReq.Signature = signatureResp.Signature

	_, err = s.wompiService.CreateTransaction(ctx, wompiReq)
	if err != nil {
		return fmt.Errorf("error creating Wompi transaction: %w", err)
	}

	return nil
}