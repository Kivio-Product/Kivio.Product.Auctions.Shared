package services

import (
	"context"
	"fmt"
	"os"
	"time"

	billingService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/billing"
	applicationLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/logging"
	domainLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/logging"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
	paymentDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/payment"
	infrastructureLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/logging"
)

type PaymentService interface {
	ProcessPaymentForCustomer(ctx context.Context, orders []*orderDomain.Order) error
}

type paymentService struct {
	wompiService   WompiService
	billingService billingService.BillingService
	logger         applicationLogging.ServiceLogger
}

func NewPaymentService(
	wompiService WompiService,
	billingService billingService.BillingService,
) PaymentService {
	loggerRepo := infrastructureLogging.GetLoggerRepository()
	return &paymentService{
		wompiService:   wompiService,
		billingService: billingService,
		logger:         applicationLogging.NewServiceLogger(loggerRepo, "PaymentService"),
	}
}

func (s *paymentService) ProcessPaymentForCustomer(ctx context.Context, orders []*orderDomain.Order) error {
	start := time.Now()

	orderIds := make([]string, len(orders))
	for i, order := range orders {
		orderIds[i] = order.OrderId
	}

	logFields := domainLogging.Fields{
		"orders_count": len(orders),
		"order_ids":    orderIds,
	}

	s.logger.LogServiceStart(ctx, "PaymentService", "ProcessPaymentForCustomer", logFields)

	if len(orders) == 0 {
		duration := time.Since(start)
		err := fmt.Errorf("no orders provided for payment processing")
		s.logger.LogServiceError(ctx, "PaymentService", "ProcessPaymentForCustomer", err, duration, logFields)
		return err
	}

	customerId := orders[0].CustomerId
	logFields["customer_id"] = customerId

	for _, order := range orders {
		if order.CustomerId != customerId {
			duration := time.Since(start)
			err := fmt.Errorf("all orders must belong to the same customer")
			s.logger.LogServiceError(ctx, "PaymentService", "ProcessPaymentForCustomer", err, duration, logFields)
			return err
		}
		if order.WompiIdPayment == "" {
			duration := time.Since(start)
			err := fmt.Errorf("order %s does not have WompiIdPayment", order.OrderId)
			s.logger.LogServiceError(ctx, "PaymentService", "ProcessPaymentForCustomer", err, duration, domainLogging.Fields{
				"customer_id": customerId,
				"order_id":    order.OrderId,
			})
			return err
		}
	}

	billingReference, err := s.billingService.GetBillingReferenceByOrderId(ctx, orders[0].OrderId)
	if err != nil {
		duration := time.Since(start)
		wrappedErr := fmt.Errorf("error getting billing reference: %w", err)
		s.logger.LogServiceError(ctx, "PaymentService", "ProcessPaymentForCustomer", wrappedErr, duration, logFields)
		return wrappedErr
	}

	logFields["billing_reference"] = billingReference

	var totalAmount int64
	for _, order := range orders {
		amountInCents := int64(float64(order.OfferedAmount) * 100)
		totalAmount += amountInCents
	}

	logFields["total_amount_cents"] = totalAmount

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
		duration := time.Since(start)
		wrappedErr := fmt.Errorf("error converting WompiIdPayment to int64: %w", err)
		s.logger.LogServiceError(ctx, "PaymentService", "ProcessPaymentForCustomer", wrappedErr, duration, domainLogging.Fields{
			"customer_id":      customerId,
			"wompi_id_payment": orders[0].WompiIdPayment,
		})
		return wrappedErr
	}
	wompiReq.PaymentSourceId = paymentSourceId
	logFields["payment_source_id"] = paymentSourceId

	integritySecret := os.Getenv("WOMPI_INTEGRITY_SECRET")
	if integritySecret == "" {
		duration := time.Since(start)
		err := fmt.Errorf("WOMPI_INTEGRITY_SECRET not configured")
		s.logger.LogServiceError(ctx, "PaymentService", "ProcessPaymentForCustomer", err, duration, logFields)
		return err
	}

	s.logger.LogBusinessEvent(ctx, "payment_signature_generation", domainLogging.Fields{
		"customer_id":       customerId,
		"billing_reference": billingReference,
		"amount_cents":      totalAmount,
	})

	signatureResp, err := s.wompiService.GenerateIntegritySignature(ctx, billingReference, totalAmount, "COP", integritySecret, nil)
	if err != nil {
		duration := time.Since(start)
		wrappedErr := fmt.Errorf("error generating Wompi signature: %w", err)
		s.logger.LogServiceError(ctx, "PaymentService", "ProcessPaymentForCustomer", wrappedErr, duration, logFields)
		return wrappedErr
	}
	wompiReq.Signature = signatureResp.Signature

	s.logger.LogBusinessEvent(ctx, "payment_transaction_creation", domainLogging.Fields{
		"customer_id":       customerId,
		"billing_reference": billingReference,
		"amount_cents":      totalAmount,
		"payment_source_id": paymentSourceId,
	})

	transactionResp, err := s.wompiService.CreateTransaction(ctx, wompiReq)
	if err != nil {
		duration := time.Since(start)
		wrappedErr := fmt.Errorf("error creating Wompi transaction for customer %s with total amount %d: %w", customerId, totalAmount, err)
		s.logger.LogServiceError(ctx, "PaymentService", "ProcessPaymentForCustomer", wrappedErr, duration, logFields)
		return wrappedErr
	}

	duration := time.Since(start)
	successFields := logFields
	if transactionResp != nil {
		successFields["transaction_id"] = transactionResp.Data.ID
		successFields["transaction_status"] = transactionResp.Data.Status
	}

	s.logger.LogServiceSuccess(ctx, "PaymentService", "ProcessPaymentForCustomer", duration, successFields)
	s.logger.LogBusinessEvent(ctx, "payment_completed", successFields)

	return nil
}
