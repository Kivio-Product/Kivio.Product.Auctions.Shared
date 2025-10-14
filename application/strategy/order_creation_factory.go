package strategy

import (
	"context"
	"fmt"

	integrationService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/integration"
	domainIntegration "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/integration"
	domainStrategy "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/strategy"
)

type OrderCreationStrategyFactory struct {
	integrationService integrationService.IntegrationService
	ecommerceStrategy  domainStrategy.OrderCreationStrategy
}

func NewOrderCreationStrategyFactory(
	integrationService integrationService.IntegrationService,
	ecommerceStrategy domainStrategy.OrderCreationStrategy,
) *OrderCreationStrategyFactory {
	return &OrderCreationStrategyFactory{
		integrationService: integrationService,
		ecommerceStrategy:  ecommerceStrategy,
	}
}

func (f *OrderCreationStrategyFactory) GetStrategy(ctx context.Context, source string, posID string) (domainStrategy.OrderCreationStrategy, error) {
	if source == "" || source == "local" {
		return nil, fmt.Errorf("local items do not need external order creation")
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
		fmt.Printf("[OrderCreationFactory] Using ecommerce order creation strategy for source '%s', POS %s\n", source, posID)
		return f.ecommerceStrategy, nil
	default:
		return nil, fmt.Errorf("unknown item source: %s", source)
	}
}
