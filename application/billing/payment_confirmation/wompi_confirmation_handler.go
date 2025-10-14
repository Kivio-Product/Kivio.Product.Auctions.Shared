package payment_confirmation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	paymentDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/payment"
	domainStrategy "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/strategy"
)

type WompiConfirmationHandler struct {
	orchestrator  *PaymentConfirmationOrchestrator
	offerStrategy domainStrategy.OfferProcessingStrategy
}

func NewWompiConfirmationHandler(
	orchestrator *PaymentConfirmationOrchestrator,
	offerStrategy domainStrategy.OfferProcessingStrategy,
) *WompiConfirmationHandler {
	return &WompiConfirmationHandler{
		orchestrator:  orchestrator,
		offerStrategy: offerStrategy,
	}
}

func (h *WompiConfirmationHandler) HandleConfirmation(
	ctx context.Context,
	body []byte,
) error {
	fmt.Println("Iniciando ConfirmWompiResponse")

	var webhook paymentDomain.WompiWebhook
	if err := json.Unmarshal(body, &webhook); err != nil {
		return fmt.Errorf("error al parsear el body de Wompi: %w", err)
	}

	isValid := h.validateSignature(&webhook)
	if !isValid {
		fmt.Printf("Error: firma inválida para evento Wompi con ID: %s\n", webhook.Data.Transaction.ID)
		return errors.New("firma del evento inválida")
	}

	fmt.Println("Firma del evento validada correctamente")

	tx := webhook.Data.Transaction
	billingID := tx.Reference

	state := h.mapWompiState(tx.Status)
	fmt.Printf("Estado de la transacción: %s -> %s\n", tx.Status, state)

	return h.orchestrator.ExecutePaymentConfirmation(
		ctx,
		billingID,
		state,
		tx.PaymentMethod,
		tx.ID,
		h.offerStrategy,
	)
}

func (h *WompiConfirmationHandler) validateSignature(webhook *paymentDomain.WompiWebhook) bool {
	eventSecret := os.Getenv("WOMPI_EVENT_SECRET")
	if eventSecret == "" {
		fmt.Println("Error: WOMPI_EVENT_SECRET no está configurado")
		return false
	}

	tx := webhook.Data.Transaction

	fmt.Printf("=== DEBUG WOMPI SIGNATURE VALIDATION ===\n")
	fmt.Printf("Transaction ID: '%s'\n", tx.ID)
	fmt.Printf("Transaction Status: '%s'\n", tx.Status)
	fmt.Printf("Transaction Amount: '%d'\n", tx.AmountInCents)
	fmt.Printf("Timestamp: '%d'\n", webhook.Timestamp)
	fmt.Printf("Event Secret: '%s'\n", eventSecret)

	signatureString := tx.ID + tx.Status + strconv.FormatInt(tx.AmountInCents, 10) + strconv.FormatInt(webhook.Timestamp, 10) + eventSecret

	fmt.Printf("Signature String Completo: '%s'\n", signatureString)
	fmt.Printf("Signature String (ocultando secret): '%s'\n", strings.Replace(signatureString, eventSecret, "[EVENT_SECRET]", -1))

	hash := sha256.Sum256([]byte(signatureString))
	expected := hex.EncodeToString(hash[:])

	fmt.Printf("Firma esperada (SHA256): %s\n", expected)
	fmt.Printf("Firma recibida (checksum): %s\n", webhook.Signature.Checksum)
	fmt.Printf("¿Las firmas coinciden? %t\n", strings.EqualFold(expected, webhook.Signature.Checksum))
	fmt.Printf("========================================\n")

	return strings.EqualFold(expected, webhook.Signature.Checksum)
}

func (h *WompiConfirmationHandler) mapWompiState(status string) string {
	stateMap := map[string]string{
		"APPROVED": "Approved",
		"DECLINED": "Rejected",
		"PENDING":  "Pending",
		"VOIDED":   "Error",
		"ERROR":    "Error",
	}

	if state, exists := stateMap[strings.ToUpper(status)]; exists {
		return state
	}

	return "Unknown"
}
