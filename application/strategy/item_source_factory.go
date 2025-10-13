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

// GetStrategyByItemSpec retorna el strategy basado en el Source del ItemSpec
// Este método verifica que el source coincida con una integración activa
func (f *ItemSourceFactory) GetStrategyByItemSpec(ctx context.Context, source string, posID string) (domainStrategy.ItemSourceStrategy, error) {
	// Si es local, retornar strategy local directamente
	if source == "" || source == "local" {
		return f.localSource, nil
	}

	// Para sources externos, verificar que existe integración activa
	integrations, err := f.integrationService.GetIntegrationsByPosID(ctx, posID)
	if err != nil {
		return nil, fmt.Errorf("item source is '%s' but cannot verify integrations: %w", source, err)
	}

	// Verificar que existe integración activa del tipo especificado
	hasActiveIntegration := false
	for _, integration := range integrations {
		if integration.Type == source && integration.Status == domainIntegration.Active {
			hasActiveIntegration = true
			break
		}
	}

	if !hasActiveIntegration {
		return nil, fmt.Errorf("item source is '%s' but no active '%s' integration found for POS %s", source, source, posID)
	}

	// Mapear source a strategy correspondiente
	switch source {
	case "ecommerce":
		return f.ecommerceSource, nil
	case "shopify":
		// Futuro: retornar shopify strategy
		return nil, fmt.Errorf("shopify source not implemented yet")
	case "woocommerce":
		// Futuro: retornar woocommerce strategy
		return nil, fmt.Errorf("woocommerce source not implemented yet")
	default:
		return nil, fmt.Errorf("unknown item source: %s", source)
	}
}

// GetStrategyByIsExternalLegacy es para backward compatibility con código legacy
// DEPRECATED: Usar GetStrategyByItemSpec con source en su lugar
func (f *ItemSourceFactory) GetStrategyByIsExternalLegacy(ctx context.Context, isExternal bool, posID string) (domainStrategy.ItemSourceStrategy, error) {
	if isExternal {
		// Inferir que es ecommerce (legacy behavior)
		return f.GetStrategyByItemSpec(ctx, "ecommerce", posID)
	}
	return f.localSource, nil
}
