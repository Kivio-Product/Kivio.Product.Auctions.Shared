package strategy

import (
	"context"
	"fmt"

	ecommerceService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/ecommerce"
	integrationService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/integration"
	itemSource "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/strategy/item_source"
	domainIntegration "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/integration"
	domainStrategy "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/strategy"
)

type ItemSourceFactory struct {
	integrationService integrationService.IntegrationService
	localSource        domainStrategy.ItemSourceStrategy
	ecommerceCredSvc   ecommerceService.EcommerceCredentialsService
	ecommerceSvc       ecommerceService.EcommerceService
}

func NewItemSourceFactory(
	integrationService integrationService.IntegrationService,
	localSource domainStrategy.ItemSourceStrategy,
	ecommerceCredSvc ecommerceService.EcommerceCredentialsService,
	ecommerceSvc ecommerceService.EcommerceService,
) *ItemSourceFactory {
	return &ItemSourceFactory{
		integrationService: integrationService,
		localSource:        localSource,
		ecommerceCredSvc:   ecommerceCredSvc,
		ecommerceSvc:       ecommerceSvc,
	}
}

func (f *ItemSourceFactory) GetStrategy(ctx context.Context, posID string) (domainStrategy.ItemSourceStrategy, error) {
	integrations, err := f.integrationService.GetIntegrationsByPosID(ctx, posID)
	if err != nil {
		fmt.Printf("[ItemSourceFactory] Error getting integrations for POS %s, using local strategy: %v\n", posID, err)
		return f.localSource, nil
	}

	for _, integration := range integrations {
		if integration.Type == "kivio_ecommerce" && integration.Status == domainIntegration.Active {
			fmt.Printf("[ItemSourceFactory] Found active ecommerce integration for POS %s\n", posID)
			return itemSource.NewEcommerceItemSource(f.ecommerceCredSvc, f.ecommerceSvc, posID), nil
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
	case "kivio_ecommerce":
		return itemSource.NewEcommerceItemSource(f.ecommerceCredSvc, f.ecommerceSvc, posID), nil
	default:
		return nil, fmt.Errorf("unknown item source: %s", source)
	}
}

func (f *ItemSourceFactory) GetStrategyByIsExternalLegacy(ctx context.Context, isExternal bool, posID string) (domainStrategy.ItemSourceStrategy, error) {
	if isExternal {
		return f.GetStrategyByItemSpec(ctx, "kivio_ecommerce", posID)
	}
	return f.localSource, nil
}
