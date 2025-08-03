package services

import (
	"context"

	integrationService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/integration"
	ecommerceBridge "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/ecommerce"
	ecommerceClient "github.com/Kivio-Product/Kivio.Product.Auctions.EcommerceClient"
)

type EcommerceCredentials = ecommerceClient.EcommerceCredentials

type EcommerceCredentialsService interface {
	GetCredentials(ctx context.Context, posID string) (*EcommerceCredentials, error)
}

func NewEcommerceCredentialsService(integrationService integrationService.IntegrationService) EcommerceCredentialsService {
	return ecommerceBridge.NewEcommerceCredentialsService(integrationService)
}
