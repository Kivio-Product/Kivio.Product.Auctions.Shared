package services

import (
	"context"

	ecommerceClient "github.com/Kivio-Product/Kivio.Product.Auctions.EcommerceClient"
	integrationService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/integration"
	ecommerceBridge "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/ecommerce"
)

type EcommerceCredentials = ecommerceClient.EcommerceCredentials

type EcommerceCredentialsService interface {
	GetCredentials(ctx context.Context, posID string) (*EcommerceCredentials, error)
}

func NewEcommerceCredentialsService(integrationService integrationService.IntegrationService) EcommerceCredentialsService {
	return ecommerceBridge.NewEcommerceCredentialsService(integrationService)
}
