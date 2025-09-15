package services

import (
	"context"
	"fmt"
	"time"

	applicationLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/logging"
	domainLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/logging"
	paymentDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/payment"
	wompiapi "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/api/wompi"
	infrastructureLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/logging"
)

type WompiService interface {
	GenerateIntegritySignature(ctx context.Context, reference string, amountInCents int64, currency string, integritySecret string, expirationTime *time.Time) (*paymentDomain.WompiSignatureResponse, error)
	CreateTransaction(ctx context.Context, req *paymentDomain.WompiTransactionRequest) (*paymentDomain.WompiTransactionResponse, error)
	GetAcceptanceToken(ctx context.Context) (string, error)
	GetAcceptanceTokenInfo(ctx context.Context) (*paymentDomain.AcceptanceTokenInfo, error)
	CreateCardToken(ctx context.Context, req *paymentDomain.WompiCardTokenRequest) (*paymentDomain.WompiCardTokenResponse, error)
	CreatePaymentSource(ctx context.Context, req *paymentDomain.WompiPaymentSourceRequest) (*paymentDomain.WompiPaymentSourceResponse, error)
	CreateNequiToken(ctx context.Context, phoneNumber, acceptanceToken, acceptancePersonalAuth string) (*paymentDomain.WompiNequiTokenResponse, error)
}

type wompiService struct {
	client *wompiapi.WompiClient
	logger applicationLogging.ServiceLogger
}

func NewWompiService(client *wompiapi.WompiClient) WompiService {
	loggerRepo := infrastructureLogging.GetLoggerRepository()
	return &wompiService{
		client: client,
		logger: applicationLogging.NewServiceLogger(loggerRepo, "WompiService"),
	}
}

func (s *wompiService) GenerateIntegritySignature(
	ctx context.Context,
	reference string,
	amountInCents int64,
	currency string,
	integritySecret string,
	expirationTime *time.Time,
) (*paymentDomain.WompiSignatureResponse, error) {

	req := paymentDomain.WompiSignatureRequest{
		Reference:       reference,
		AmountInCents:   amountInCents,
		Currency:        currency,
		ExpirationTime:  expirationTime,
		IntegritySecret: integritySecret,
	}

	signatureResponse, err := paymentDomain.GenerateWompiSignature(req)
	if err != nil {
		return nil, fmt.Errorf("error generando firma de integridad: %w", err)
	}

	return signatureResponse, nil
}

func (s *wompiService) CreateTransaction(ctx context.Context, req *paymentDomain.WompiTransactionRequest) (*paymentDomain.WompiTransactionResponse, error) {
	start := time.Now()

	logFields := domainLogging.Fields{
		"amount_cents":      req.AmountInCents,
		"currency":          req.Currency,
		"reference":         req.Reference,
		"payment_source_id": req.PaymentSourceId,
		"customer_email":    req.CustomerEmail,
	}

	s.logger.LogServiceStart(ctx, "WompiService", "CreateTransaction", logFields)
	s.logger.LogExternalCall(ctx, "Wompi", "CreateTransaction", 0, true, logFields)

	resp, err := s.client.CreateTransaction(req)
	duration := time.Since(start)

	if err != nil {
		s.logger.LogServiceError(ctx, "WompiService", "CreateTransaction", err, duration, logFields)
		s.logger.LogExternalCall(ctx, "Wompi", "CreateTransaction", duration, false, domainLogging.Fields{
			"error":     err.Error(),
			"reference": req.Reference,
		})
		return nil, err
	}

	successFields := logFields
	if resp != nil {
		successFields["transaction_id"] = resp.Data.ID
		successFields["transaction_status"] = resp.Data.Status
	}

	s.logger.LogServiceSuccess(ctx, "WompiService", "CreateTransaction", duration, successFields)
	s.logger.LogExternalCall(ctx, "Wompi", "CreateTransaction", duration, true, successFields)

	return resp, nil
}

func (s *wompiService) GetAcceptanceToken(ctx context.Context) (string, error) {
	return s.client.GetAcceptanceToken()
}

func (s *wompiService) GetAcceptanceTokenInfo(ctx context.Context) (*paymentDomain.AcceptanceTokenInfo, error) {
	return s.client.GetAcceptanceTokenInfo()
}

func (s *wompiService) CreateCardToken(ctx context.Context, req *paymentDomain.WompiCardTokenRequest) (*paymentDomain.WompiCardTokenResponse, error) {
	return s.client.CreateCardToken(req)
}

func (s *wompiService) CreatePaymentSource(ctx context.Context, req *paymentDomain.WompiPaymentSourceRequest) (*paymentDomain.WompiPaymentSourceResponse, error) {
	return s.client.CreatePaymentSource(req)
}

func (s *wompiService) CreateNequiToken(ctx context.Context, phoneNumber, acceptanceToken, acceptancePersonalAuth string) (*paymentDomain.WompiNequiTokenResponse, error) {
	return s.client.CreateNequiToken(phoneNumber, acceptanceToken, acceptancePersonalAuth)
}
