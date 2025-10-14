package strategy

import (
	"context"
	"fmt"

	integrationService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/integration"
	domainIntegration "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/integration"
	domainStrategy "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/strategy"
)

type InvoiceStrategyFactory struct {
	integrationService integrationService.IntegrationService
	siigoStrategy      domainStrategy.InvoiceStrategy
	ecommerceStrategy  domainStrategy.InvoiceStrategy
}

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

func (f *InvoiceStrategyFactory) GetStrategy(ctx context.Context, posID string, source string) (domainStrategy.InvoiceStrategy, error) {
	if source == "" || source == "local" {
		fmt.Printf("[InvoiceStrategyFactory] Item source is local, using Siigo strategy for POS %s\n", posID)
		return f.siigoStrategy, nil
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
		fmt.Printf("[InvoiceStrategyFactory] Item source is ecommerce and has active integration, using ecommerce order strategy for POS %s\n", posID)
		return f.ecommerceStrategy, nil
	case "shopify":
		return nil, fmt.Errorf("shopify invoice strategy not implemented yet")
	case "woocommerce":
		return nil, fmt.Errorf("woocommerce invoice strategy not implemented yet")
	default:
		return nil, fmt.Errorf("unknown item source: %s", source)
	}
}

func (f *InvoiceStrategyFactory) GetStrategyForOrders(ctx context.Context, posID string, itemSources []string) (domainStrategy.InvoiceStrategy, error) {
	if len(itemSources) == 0 {
		return nil, fmt.Errorf("no items provided to determine invoice strategy")
	}

	firstSource := itemSources[0]
	for _, source := range itemSources {
		if source != firstSource {
			return nil, fmt.Errorf("cannot invoice mixed sources (%s and %s) in the same billing", firstSource, source)
		}
	}

	return f.GetStrategy(ctx, posID, firstSource)
}
