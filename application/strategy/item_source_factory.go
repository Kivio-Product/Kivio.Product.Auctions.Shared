package strategy

import (
	"context"
	"fmt"

	integrationService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/integration"
	domainIntegration "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/integration"
	domainStrategy "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/strategy"
)

type ItemSourceFactory struct {
	integrationService integrationService.IntegrationService
	localSource        domainStrategy.ItemSourceStrategy
	ecommerceSource    domainStrategy.ItemSourceStrategy
}

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

func (f *ItemSourceFactory) GetStrategy(ctx context.Context, posID string) (domainStrategy.ItemSourceStrategy, error) {
	integrations, err := f.integrationService.GetIntegrationsByPosID(ctx, posID)
	if err != nil {
		fmt.Printf("[ItemSourceFactory] Error getting integrations for POS %s, using local strategy: %v\n", posID, err)
		return f.localSource, nil
	}

	for _, integration := range integrations {
		if integration.Type == "ecommerce" && integration.Status == domainIntegration.Active {
			fmt.Printf("[ItemSourceFactory] Found active ecommerce integration for POS %s\n", posID)
			return f.ecommerceSource, nil
		}
	}

	fmt.Printf("[ItemSourceFactory] No active ecommerce integration for POS %s, using local strategy\n", posID)
	return f.localSource, nil
}

func (f *ItemSourceFactory) GetStrategyByItemSpec(ctx context.Context, source string, posID string) (domainStrategy.ItemSourceStrategy, error) {
	if source == "" || source == "local" {
		return f.localSource, nil
	}

	integrations, err := f.integrationService.GetIntegrationsByPosID(ctx, posID)
	if err != nil {
		return nil, fmt.Errorf("item source is '%s' but cannot verify integrations: %w", source, err)
	}

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

	switch source {
	case "ecommerce":
		return f.ecommerceSource, nil
	default:
		return nil, fmt.Errorf("unknown item source: %s", source)
	}
}

func (f *ItemSourceFactory) GetStrategyByIsExternalLegacy(ctx context.Context, isExternal bool, posID string) (domainStrategy.ItemSourceStrategy, error) {
	if isExternal {
		return f.GetStrategyByItemSpec(ctx, "ecommerce", posID)
	}
	return f.localSource, nil
}
