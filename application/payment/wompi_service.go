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
	CreateTransaction(ctx context.Context, reference string, amountInCents int64, currency string, publicKey string, integritySecret string, redirectURL string, expirationTime *time.Time) (*paymentDomain.WompiTransaction, error)
	GetAcceptanceToken(ctx context.Context) (string, error)
	GetAcceptanceTokenInfo(ctx context.Context) (*paymentDomain.AcceptanceTokenInfo, error)
	CreateCardToken(ctx context.Context, req *paymentDomain.WompiCardTokenRequest) (*paymentDomain.WompiCardTokenResponse, error)
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

func (s *wompiService) CreateTransaction(
	ctx context.Context,
	reference string,
	amountInCents int64,
	currency string,
	publicKey string,
	integritySecret string,
	redirectURL string,
	expirationTime *time.Time,
) (*paymentDomain.WompiTransaction, error) {

	signatureResponse, err := s.GenerateIntegritySignature(ctx, reference, amountInCents, currency, integritySecret, expirationTime)
	if err != nil {
		return nil, fmt.Errorf("error generando firma para la transacción: %w", err)
	}

	transaction := &paymentDomain.WompiTransaction{
		Reference:      signatureResponse.Reference,
		AmountInCents:  signatureResponse.AmountInCents,
		Currency:       signatureResponse.Currency,
		ExpirationTime: signatureResponse.ExpirationTime,
		Signature:      signatureResponse.Signature,
		PublicKey:      publicKey,
		RedirectURL:    redirectURL,
	}

	return transaction, nil
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
