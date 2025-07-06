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
