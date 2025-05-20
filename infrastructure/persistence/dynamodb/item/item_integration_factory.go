package infrastructure

import (
	"fmt"

	integrationRepository "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/integration"
)

type ItemIntegrationFactory struct {
	googleSheetsStrategy *GoogleSheetsStrategy
	ecommerceStrategy    *EcommerceStrategy
}

func NewItemIntegrationFactory(
	googleSheetsRepo integrationRepository.GoogleSheetsRepository,
	integrationRepo integrationRepository.IntegrationRepository,
	ecommerceRepo integrationRepository.EcommerceRepository,
) *ItemIntegrationFactory {
	return &ItemIntegrationFactory{
		googleSheetsStrategy: NewGoogleSheetsStrategy(googleSheetsRepo, integrationRepo),
		ecommerceStrategy:    NewEcommerceStrategy(ecommerceRepo, integrationRepo),
	}
}

func (f *ItemIntegrationFactory) GetStrategy(integrationType string) (ItemIntegrationStrategy, error) {
	switch integrationType {
	case "google_sheets":
		return f.googleSheetsStrategy, nil
	case "kivio_ecommerce":
		return f.ecommerceStrategy, nil
	default:
		return nil, fmt.Errorf("unsupported integration type: %s", integrationType)
	}
}
