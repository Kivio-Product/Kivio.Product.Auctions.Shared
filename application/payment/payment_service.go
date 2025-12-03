package services

import (
	"context"
	"fmt"
	"os"
	"time"

	billingService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/billing"
	applicationLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/logging"
	"github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/logging"
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
	serviceLogger  *applicationLogging.ServiceLogger
	eventLogger    *logging.DomainEventLogger
}

func NewPaymentService(
	wompiService WompiService,
	billingService billingService.BillingService,
) PaymentService {
	loggerRepo := infrastructureLogging.GetLoggerRepository()
	serviceLogger := applicationLogging.NewServiceLogger(loggerRepo, "PaymentService")
	eventLogger := logging.NewDomainEventLogger(loggerRepo.GetLogger())

	return &paymentService{
		wompiService:   wompiService,
		billingService: billingService,
		serviceLogger:  serviceLogger,
		eventLogger:    eventLogger,
	}
}

func (s *paymentService) ProcessPaymentForCustomer(ctx context.Context, orders []*orderDomain.Order) error {
	start := time.Now()

	orderIds := make([]string, len(orders))
	var totalAmount int64
	for i, order := range orders {
		orderIds[i] = order.OrderId
		totalAmount += order.OfferedAmount
	}

	s.serviceLogger.LogServiceStart(ctx, "ProcessPaymentForCustomer", map[string]interface{}{
		"order_count":  len(orders),
		"order_ids":    orderIds,
		"total_amount": totalAmount,
		"customer_id":  orders[0].CustomerId,
	})

	if len(orders) == 0 {
		err := fmt.Errorf("no orders provided for payment processing")
		s.serviceLogger.LogServiceError(ctx, "ProcessPaymentForCustomer", err, map[string]interface{}{
			"error": "no_orders_provided",
		})
		return err
	}

	customerId := orders[0].CustomerId
	for _, order := range orders {
		if order.CustomerId != customerId {
			err := fmt.Errorf("all orders must belong to the same customer")
			s.serviceLogger.LogServiceError(ctx, "ProcessPaymentForCustomer", err, map[string]interface{}{
				"customer_id":    customerId,
				"order_id":       order.OrderId,
				"order_customer": order.CustomerId,
				"error":          "customer_mismatch",
			})
			return err
		}
		if order.WompiIdPayment == "" {
			err := fmt.Errorf("order %s does not have WompiIdPayment", order.OrderId)
			s.serviceLogger.LogServiceError(ctx, "ProcessPaymentForCustomer", err, map[string]interface{}{
				"order_id":    order.OrderId,
				"customer_id": customerId,
				"error":       "missing_wompi_payment_id",
			})
			return err
		}
	}

	billingReference, err := s.billingService.GetBillingReferenceByOrderId(ctx, orders[0].OrderId)
	if err != nil {
		s.serviceLogger.LogServiceError(ctx, "ProcessPaymentForCustomer", err, map[string]interface{}{
			"order_id":    orders[0].OrderId,
			"customer_id": customerId,
			"error":       "failed_to_get_billing_reference",
		})
		return fmt.Errorf("error getting billing reference: %w", err)
	}

	var totalAmountCents int64
	for _, order := range orders {
		amountInCents := int64(float64(order.OfferedAmount) * 100)
		totalAmountCents += amountInCents
	}

	wompiReq := &paymentDomain.WompiTransactionRequest{
		AmountInCents:   totalAmountCents,
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
		s.serviceLogger.LogServiceError(ctx, "ProcessPaymentForCustomer", err, map[string]interface{}{
			"wompi_id_payment": orders[0].WompiIdPayment,
			"customer_id":      customerId,
			"error":            "failed_to_convert_payment_source_id",
		})
		return fmt.Errorf("error converting WompiIdPayment to int64: %w", err)
	}
	wompiReq.PaymentSourceId = paymentSourceId

	integritySecret := os.Getenv("WOMPI_INTEGRITY_SECRET")
	if integritySecret == "" {
		err := fmt.Errorf("WOMPI_INTEGRITY_SECRET not configured")
		s.serviceLogger.LogServiceError(ctx, "ProcessPaymentForCustomer", err, map[string]interface{}{
			"customer_id": customerId,
			"error":       "missing_integrity_secret",
		})
		return err
	}

	s.serviceLogger.LogExternalAPICall(ctx, "Wompi", "/signatures", 0, false, map[string]interface{}{
		"operation":         "generate_integrity_signature",
		"billing_reference": billingReference,
		"amount_cents":      totalAmountCents,
	})

	signatureResp, err := s.wompiService.GenerateIntegritySignature(ctx, billingReference, totalAmountCents, "COP", integritySecret, nil)
	if err != nil {
		s.serviceLogger.LogServiceError(ctx, "ProcessPaymentForCustomer", err, map[string]interface{}{
			"billing_reference": billingReference,
			"customer_id":       customerId,
			"amount_cents":      totalAmountCents,
			"error":             "failed_to_generate_signature",
		})
		return fmt.Errorf("error generating Wompi signature: %w", err)
	}
	wompiReq.Signature = signatureResp.Signature

	s.serviceLogger.LogExternalAPICall(ctx, "Wompi", "/transactions", 0, false, map[string]interface{}{
		"operation":         "create_transaction",
		"billing_reference": billingReference,
		"amount_cents":      totalAmountCents,
		"payment_source_id": paymentSourceId,
	})

	transactionResp, err := s.wompiService.CreateTransaction(ctx, wompiReq)
	if err != nil {
		s.serviceLogger.LogServiceError(ctx, "ProcessPaymentForCustomer", err, map[string]interface{}{
			"customer_id":       customerId,
			"amount_cents":      totalAmountCents,
			"billing_reference": billingReference,
			"payment_source_id": paymentSourceId,
			"error":             "failed_to_create_transaction",
		})
		return fmt.Errorf("error creating Wompi transaction for customer %s with total amount %d: %w", customerId, totalAmountCents, err)
	}

	transactionID := transactionResp.Data.ID
	initialStatus := transactionResp.Data.Status

	fmt.Printf("[Payment] Transaction created: ID=%s, Initial Status=%s\n", transactionID, initialStatus)

	if initialStatus == "APPROVED" {
		fmt.Printf("[Payment] ✓ Payment APPROVED immediately for customer %s (Transaction: %s)\n", customerId, transactionID)
		s.eventLogger.LogPaymentProcessed(ctx, transactionID, orders[0].OrderId, initialStatus, float64(totalAmountCents)/100)
		s.serviceLogger.LogServiceEnd(ctx, "ProcessPaymentForCustomer", time.Since(start), map[string]interface{}{
			"customer_id":        customerId,
			"order_count":        len(orders),
			"total_amount_cents": totalAmountCents,
			"billing_reference":  billingReference,
			"transaction_id":     transactionID,
			"transaction_status": initialStatus,
			"success":            true,
		})
		return nil
	}

	if initialStatus == "DECLINED" || initialStatus == "VOIDED" || initialStatus == "ERROR" {
		err := fmt.Errorf("payment %s for customer %s (status: %s)", initialStatus, customerId, initialStatus)
		fmt.Printf("[Payment] ✗ Payment FAILED for customer %s: %s (Transaction: %s)\n", customerId, initialStatus, transactionID)
		s.eventLogger.LogPaymentProcessed(ctx, transactionID, orders[0].OrderId, initialStatus, float64(totalAmountCents)/100)
		s.serviceLogger.LogServiceError(ctx, "ProcessPaymentForCustomer", err, map[string]interface{}{
			"customer_id":        customerId,
			"transaction_id":     transactionID,
			"transaction_status": initialStatus,
			"error":              "payment_declined",
		})
		return err
	}

	if initialStatus == "PENDING" {
		fmt.Printf("[Payment] Payment PENDING for customer %s, querying status... (Transaction: %s)\n", customerId, transactionID)

		maxRetries := 3
		retryDelay := 2 * time.Second
		finalStatus := initialStatus

		for i := 0; i < maxRetries; i++ {
			time.Sleep(retryDelay)

			statusResp, err := s.wompiService.GetTransactionStatus(ctx, transactionID)
			if err != nil {
				fmt.Printf("[Payment] Warning: Could not query transaction status (attempt %d/%d): %v\n", i+1, maxRetries, err)
				continue
			}

			finalStatus = statusResp.Data.Status
			fmt.Printf("[Payment] Transaction status check %d/%d: %s\n", i+1, maxRetries, finalStatus)

			if finalStatus == "APPROVED" {
				fmt.Printf("[Payment] ✓ Payment APPROVED after polling for customer %s (Transaction: %s)\n", customerId, transactionID)
				s.eventLogger.LogPaymentProcessed(ctx, transactionID, orders[0].OrderId, finalStatus, float64(totalAmountCents)/100)
				s.serviceLogger.LogServiceEnd(ctx, "ProcessPaymentForCustomer", time.Since(start), map[string]interface{}{
					"customer_id":        customerId,
					"order_count":        len(orders),
					"total_amount_cents": totalAmountCents,
					"billing_reference":  billingReference,
					"transaction_id":     transactionID,
					"transaction_status": finalStatus,
					"polling_attempts":   i + 1,
					"success":            true,
				})
				return nil
			}

			if finalStatus == "DECLINED" || finalStatus == "VOIDED" || finalStatus == "ERROR" {
				err := fmt.Errorf("payment %s for customer %s after polling (status: %s)", finalStatus, customerId, finalStatus)
				fmt.Printf("[Payment] ✗ Payment FAILED after polling for customer %s: %s (Transaction: %s)\n", customerId, finalStatus, transactionID)
				s.eventLogger.LogPaymentProcessed(ctx, transactionID, orders[0].OrderId, finalStatus, float64(totalAmountCents)/100)
				s.serviceLogger.LogServiceError(ctx, "ProcessPaymentForCustomer", err, map[string]interface{}{
					"customer_id":        customerId,
					"transaction_id":     transactionID,
					"transaction_status": finalStatus,
					"polling_attempts":   i + 1,
					"error":              "payment_declined_after_polling",
				})
				return err
			}
		}

		err := fmt.Errorf("payment still PENDING for customer %s after %d retries", customerId, maxRetries)
		fmt.Printf("[Payment] ✗ Payment timeout for customer %s (still PENDING after %d retries, Transaction: %s)\n", customerId, maxRetries, transactionID)
		s.eventLogger.LogPaymentProcessed(ctx, transactionID, orders[0].OrderId, finalStatus, float64(totalAmountCents)/100)
		s.serviceLogger.LogServiceError(ctx, "ProcessPaymentForCustomer", err, map[string]interface{}{
			"customer_id":        customerId,
			"transaction_id":     transactionID,
			"transaction_status": finalStatus,
			"polling_attempts":   maxRetries,
			"error":              "payment_timeout",
		})
		return err
	}

	err = fmt.Errorf("unknown payment status '%s' for customer %s", initialStatus, customerId)
	fmt.Printf("[Payment] ✗ Unknown payment status for customer %s: %s (Transaction: %s)\n", customerId, initialStatus, transactionID)
	s.serviceLogger.LogServiceError(ctx, "ProcessPaymentForCustomer", err, map[string]interface{}{
		"customer_id":        customerId,
		"transaction_id":     transactionID,
		"transaction_status": initialStatus,
		"error":              "unknown_status",
	})
	return err
}
