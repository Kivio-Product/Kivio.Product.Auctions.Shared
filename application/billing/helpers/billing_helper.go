package helpers

import (
	"context"
	"fmt"
	"time"

	billingDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/billing"
	billingInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/billing"
)

type BillingHelper struct {
	billingRepo billingInfrastructure.BillingRepository
}

func NewBillingHelper(billingRepo billingInfrastructure.BillingRepository) *BillingHelper {
	return &BillingHelper{
		billingRepo: billingRepo,
	}
}

func (h *BillingHelper) GetAndValidateBilling(ctx context.Context, billingID string) (*billingDomain.Billing, error) {
	fmt.Printf("Buscando facturación con ID: %s\n", billingID)

	billing, err := h.billingRepo.GetBillingByID(ctx, billingID)
	if err != nil {
		fmt.Printf("Error: no se encontró facturación con ID: %s - %v\n", billingID, err)
		return nil, fmt.Errorf("no se encontró facturación con ID: %s", billingID)
	}

	fmt.Printf("Facturación encontrada: %+v\n", billing)
	return billing, nil
}

func (h *BillingHelper) UpdateBillingState(ctx context.Context, billing *billingDomain.Billing, state, paymentMethod, transactionID string) error {
	billing.State = state
	billing.PayloadType = paymentMethod
	billing.TransactionId = transactionID
	billing.ConfirmedAt = time.Now()

	fmt.Printf("Actualizando facturación: State=%s, PayloadType=%s, TransactionId=%s, ConfirmedAt=%v\n",
		billing.State, billing.PayloadType, billing.TransactionId, billing.ConfirmedAt)

	err := h.billingRepo.UpdateBilling(ctx, billing)
	if err != nil {
		fmt.Printf("Error al actualizar la facturación: %v\n", err)
		return fmt.Errorf("error al actualizar la facturación: %v", err)
	}

	return nil
}
