package payment_confirmation

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	paymentDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/payment"
)

// PayUConfirmationHandler maneja la confirmación de pagos de PayU
type PayUConfirmationHandler struct {
	orchestrator *PaymentConfirmationOrchestrator
}

func NewPayUConfirmationHandler(
	orchestrator *PaymentConfirmationOrchestrator,
) *PayUConfirmationHandler {
	return &PayUConfirmationHandler{
		orchestrator: orchestrator,
	}
}

func (h *PayUConfirmationHandler) HandleConfirmation(
	ctx context.Context,
	res *paymentDomain.ConfirmationResponse,
	secretKey string,
) error {
	fmt.Println("Iniciando ConfirmPayUResponse")

	if res == nil || res.ReferenceSale == "" {
		fmt.Println("Error: confirmación nula o referencia de venta vacía")
		return errors.New("referencia inválida")
	}

	fmt.Printf("Datos de confirmación: MerchantId=%s, ReferenceSale=%s, Value=%s, Currency=%s, StatePol=%d\n",
		res.MerchantId, res.ReferenceSale, res.ValueStr, res.Currency, res.StatePol)

	isValid := h.validateSignature(secretKey, res.MerchantId, res.ReferenceSale, res.ValueStr, res.Currency, res.StatePol, res.Sign)
	if !isValid {
		fmt.Printf("Error: firma inválida para transacción %s\n", res.ReferenceSale)
		return errors.New("firma inválida")
	}

	fmt.Println("Firma validada correctamente")

	state := h.mapPayUState(res.StatePol)
	fmt.Printf("Estado de la transacción: %d -> %s\n", res.StatePol, state)

	return h.orchestrator.ExecutePaymentConfirmation(
		ctx,
		res.ReferenceSale,
		state,
		res.PaymentMethod,
		res.TransactionId,
	)
}

func (h *PayUConfirmationHandler) validateSignature(
	secretKey, merchantId, referenceSale, valueStr, currency string,
	statePol int,
	incomingSignature string,
) bool {
	value, _ := strconv.ParseFloat(valueStr, 64)
	fmt.Printf("Valor original: %s, Convertido a float: %f\n", valueStr, value)

	var formattedValue string
	if math.Mod(value*100, 10) == 0 {
		formattedValue = fmt.Sprintf("%.1f", value)
	} else {
		formattedValue = fmt.Sprintf("%.2f", value)
	}

	fmt.Printf("Valor formateado: %s\n", formattedValue)

	signatureString := fmt.Sprintf("%s~%s~%s~%s~%s~%d",
		secretKey, merchantId, referenceSale, formattedValue, currency, statePol)

	fmt.Printf("String para firma (ocultando clave secreta): [SECRET]~%s~%s~%s~%s~%d\n",
		merchantId, referenceSale, formattedValue, currency, statePol)

	hash := md5.Sum([]byte(signatureString))
	expected := hex.EncodeToString(hash[:])

	fmt.Printf("Firma esperada: %s\n", expected)
	fmt.Printf("Firma recibida: %s\n", incomingSignature)
	fmt.Printf("¿Las firmas coinciden? %t\n", strings.EqualFold(expected, incomingSignature))

	return strings.EqualFold(expected, incomingSignature)
}

func (h *PayUConfirmationHandler) mapPayUState(statePol int) string {
	stateMap := map[int]string{
		4:   "Approved",
		6:   "Rejected",
		104: "Error",
		7:   "Pending",
	}

	if state, exists := stateMap[statePol]; exists {
		return state
	}

	return "Unknown"
}
