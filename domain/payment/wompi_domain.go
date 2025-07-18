package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

type WompiTransaction struct {
	Reference      string     `json:"reference"`
	AmountInCents  int64      `json:"amount_in_cents"`
	Currency       string     `json:"currency"`
	ExpirationTime *time.Time `json:"expiration_time,omitempty"`
	Signature      string     `json:"signature"`
	PublicKey      string     `json:"public_key"`
	RedirectURL    string     `json:"redirect_url,omitempty"`
}

type WompiSignatureRequest struct {
	Reference       string     `json:"reference"`
	AmountInCents   int64      `json:"amount_in_cents"`
	Currency        string     `json:"currency"`
	ExpirationTime  *time.Time `json:"expiration_time,omitempty"`
	IntegritySecret string     `json:"integrity_secret"`
}

type WompiSignatureResponse struct {
	Signature      string     `json:"signature"`
	Reference      string     `json:"reference"`
	AmountInCents  int64      `json:"amount_in_cents"`
	Currency       string     `json:"currency"`
	ExpirationTime *time.Time `json:"expiration_time,omitempty"`
}

// https://docs.wompi.co/docs/colombia/tokens-de-aceptacion/
type PresignedToken struct {
	AcceptanceToken string `json:"acceptance_token"`
	Permalink       string `json:"permalink"`
	Type            string `json:"type"`
}

type AcceptanceTokenInfo struct {
	PresignedAcceptance       PresignedToken `json:"presigned_acceptance"`
	PresignedPersonalDataAuth PresignedToken `json:"presigned_personal_data_auth"`
}

type WompiMerchantResponse struct {
	Data struct {
		PresignedAcceptance       PresignedToken `json:"presigned_acceptance"`
		PresignedPersonalDataAuth PresignedToken `json:"presigned_personal_data_auth"`
	} `json:"data"`
}

type WompiCardTokenRequest struct {
	Number     string `json:"number"`
	ExpMonth   string `json:"exp_month"`
	ExpYear    string `json:"exp_year"`
	CVC        string `json:"cvc"`
	CardHolder string `json:"card_holder"`
}

type WompiCardTokenResponse struct {
	Status string `json:"status"`
	Data   struct {
		ID         string `json:"id"`
		Status     string `json:"status"`
		Brand      string `json:"brand"`
		Name       string `json:"name"`
		LastFour   string `json:"last_four"`
		ExpYear    string `json:"exp_year"`
		ExpMonth   string `json:"exp_month"`
		CardHolder string `json:"card_holder"`
	} `json:"data"`
}

func GenerateWompiSignature(req WompiSignatureRequest) (*WompiSignatureResponse, error) {
	if req.Reference == "" {
		return nil, fmt.Errorf("la referencia no puede estar vacía")
	}
	if req.AmountInCents <= 0 {
		return nil, fmt.Errorf("el monto debe ser mayor a cero")
	}
	if req.Currency == "" {
		return nil, fmt.Errorf("la moneda no puede estar vacía")
	}
	if req.IntegritySecret == "" {
		return nil, fmt.Errorf("el secreto de integridad no puede estar vacío")
	}

	var signatureString string

	if req.ExpirationTime != nil {
		expirationStr := req.ExpirationTime.Format("2006-01-02T15:04:05.000Z")
		signatureString = fmt.Sprintf("%s%d%s%s%s",
			req.Reference,
			req.AmountInCents,
			req.Currency,
			expirationStr,
			req.IntegritySecret)
	} else {
		signatureString = fmt.Sprintf("%s%d%s%s",
			req.Reference,
			req.AmountInCents,
			req.Currency,
			req.IntegritySecret)
	}

	hash := sha256.Sum256([]byte(signatureString))
	signature := hex.EncodeToString(hash[:])

	return &WompiSignatureResponse{
		Signature:      signature,
		Reference:      req.Reference,
		AmountInCents:  req.AmountInCents,
		Currency:       req.Currency,
		ExpirationTime: req.ExpirationTime,
	}, nil
}
