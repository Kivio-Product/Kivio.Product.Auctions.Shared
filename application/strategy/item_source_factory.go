package strategy

import (
	"context"
	"fmt"

	integrationService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/integration"
	domainIntegration "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/integration"
	domainStrategy "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/strategy"
)

// ItemSourceFactory es el factory que determina qué strategy usar basado en las integraciones del POS
type ItemSourceFactory struct {
	integrationService integrationService.IntegrationService
	localSource        domainStrategy.ItemSourceStrategy
	ecommerceSource    domainStrategy.ItemSourceStrategy
}

// NewItemSourceFactory crea una nueva instancia del factory
func NewItemSourceFactory(
	integrationService integrationService.IntegrationService,
	localSource domainStrategy.ItemSourceStrategy,
	ecommerceSource domainStrategy.ItemSourceStrategy,
) *ItemSourceFactory {
	return &ItemSourceFactory{
		integrationService: integrationService,
		localSource:        localSource,
		ecommerceSource:    ecommerceSource,
	}
}

// GetStrategy retorna el strategy apropiado basado en las integraciones del POS
// Primero consulta las integraciones del POS, si tiene ecommerce activo usa ese strategy,
// de lo contrario usa el strategy local
func (f *ItemSourceFactory) GetStrategy(ctx context.Context, posID string) (domainStrategy.ItemSourceStrategy, error) {
	// 1. Consultar integraciones del punto de venta
	integrations, err := f.integrationService.GetIntegrationsByPosID(ctx, posID)
	if err != nil {
		// Si hay error consultando integrations, usar strategy local como default
		fmt.Printf("[ItemSourceFactory] Error getting integrations for POS %s, using local strategy: %v\n", posID, err)
		return f.localSource, nil
	}

	// 2. Verificar si tiene integración de ecommerce activa
	for _, integration := range integrations {
		if integration.Type == "ecommerce" && integration.Status == domainIntegration.Active {
			fmt.Printf("[ItemSourceFactory] Found active ecommerce integration for POS %s\n", posID)
			return f.ecommerceSource, nil
		}
	}

	// 3. Default: source local (items de DynamoDB)
	fmt.Printf("[ItemSourceFactory] No active ecommerce integration for POS %s, using local strategy\n", posID)
	return f.localSource, nil
}

// GetStrategyByItemSpec retorna el strategy basado en el flag IsExternal del ItemSpec
// Este método es útil cuando ya tenemos el ItemSpec y queremos determinar el strategy
func (f *ItemSourceFactory) GetStrategyByItemSpec(ctx context.Context, isExternal bool, posID string) (domainStrategy.ItemSourceStrategy, error) {
	if isExternal {
		// Verificar que realmente tiene integración activa
		integrations, err := f.integrationService.GetIntegrationsByPosID(ctx, posID)
		if err != nil {
			return nil, fmt.Errorf("item marked as external but cannot verify integrations: %w", err)
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

		return f.ecommerceSource, nil
	}

	return f.localSource, nil
}
