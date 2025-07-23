package services

import (
	"context"
	"fmt"
	"time"

	paymentDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/payment"
	wompiapi "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/api/wompi"
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
}

func NewWompiService(client *wompiapi.WompiClient) WompiService {
	return &wompiService{client: client}
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
	return s.client.CreateTransaction(req)
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
