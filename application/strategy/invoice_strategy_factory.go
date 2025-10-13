package strategy

import (
	"context"
	"fmt"

	integrationService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/integration"
	domainIntegration "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/integration"
	domainStrategy "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/strategy"
)

// InvoiceStrategyFactory determina qué strategy de facturación usar
// Basado en si el item es local (Siigo) o externo (Order en ecommerce)
type InvoiceStrategyFactory struct {
	integrationService  integrationService.IntegrationService
	siigoStrategy       domainStrategy.InvoiceStrategy
	ecommerceStrategy   domainStrategy.InvoiceStrategy
}

// NewInvoiceStrategyFactory crea una nueva instancia del factory
func NewInvoiceStrategyFactory(
	integrationService integrationService.IntegrationService,
	siigoStrategy domainStrategy.InvoiceStrategy,
	ecommerceStrategy domainStrategy.InvoiceStrategy,
) *InvoiceStrategyFactory {
	return &InvoiceStrategyFactory{
		integrationService: integrationService,
		siigoStrategy:      siigoStrategy,
		ecommerceStrategy:  ecommerceStrategy,
	}
}

// GetStrategy retorna el strategy apropiado basado en:
// 1. Las integraciones del POS
// 2. Si el item es local o externo (isExternal flag)
func (f *InvoiceStrategyFactory) GetStrategy(ctx context.Context, posID string, isExternal bool) (domainStrategy.InvoiceStrategy, error) {
	// Si el item NO es externo, siempre usar Siigo
	if !isExternal {
		fmt.Printf("[InvoiceStrategyFactory] Item is local, using Siigo strategy for POS %s\n", posID)
		return f.siigoStrategy, nil
	}

	// Si el item ES externo, verificar que tiene integración de ecommerce activa
	integrations, err := f.integrationService.GetIntegrationsByPosID(ctx, posID)
	if err != nil {
		return nil, fmt.Errorf("item is external but cannot verify integrations: %w", err)
	}

	hasActiveEcommerce := false
	for _, integration := range integrations {
		if integration.Type == "ecommerce" && integration.Status == domainIntegration.Active {
			hasActiveEcommerce = true
			break
		}
	}

	if !hasActiveEcommerce {
		return nil, fmt.Errorf("item marked as external but no active ecommerce integration found for POS %s", posID)
	}

	fmt.Printf("[InvoiceStrategyFactory] Item is external and has active ecommerce, using ecommerce order strategy for POS %s\n", posID)
	return f.ecommerceStrategy, nil
}

// GetStrategyForOrders determina el strategy basado en múltiples ordenes
// Si todas son locales -> Siigo
// Si todas son externas -> Ecommerce
// Si hay mix -> Error (no se puede facturar mix de items locales y externos juntos)
func (f *InvoiceStrategyFactory) GetStrategyForOrders(ctx context.Context, posID string, itemsAreExternal []bool) (domainStrategy.InvoiceStrategy, error) {
	if len(itemsAreExternal) == 0 {
		return nil, fmt.Errorf("no items provided to determine invoice strategy")
	}

	// Verificar consistencia: todos deben ser del mismo tipo
	firstIsExternal := itemsAreExternal[0]
	for _, isExternal := range itemsAreExternal {
		if isExternal != firstIsExternal {
			return nil, fmt.Errorf("cannot invoice mixed local and external items in the same billing")
		}
	}

	// Todos son del mismo tipo, usar el strategy correspondiente
	return f.GetStrategy(ctx, posID, firstIsExternal)
}
