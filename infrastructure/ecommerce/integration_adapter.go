package ecommerce

import (
	"context"

	ecommerceClient "github.com/Kivio-Product/Kivio.Product.Auctions.EcommerceClient"
	integrationService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/integration"
)

type IntegrationServiceAdapter struct {
	integrationService integrationService.IntegrationService
}

func NewIntegrationServiceAdapter(service integrationService.IntegrationService) ecommerceClient.IntegrationService {
	return &IntegrationServiceAdapter{
		integrationService: service,
	}
}

func (a *IntegrationServiceAdapter) GetIntegrationsByPosID(ctx context.Context, posID string) ([]*ecommerceClient.IntegrationResponse, error) {
	integrations, err := a.integrationService.GetIntegrationsByPosID(ctx, posID)
	if err != nil {
		return nil, err
	}

	result := make([]*ecommerceClient.IntegrationResponse, len(integrations))
	for i, integration := range integrations {
		configs := make([]ecommerceClient.IntegrationConfigResponse, len(integration.Configs))
		for j, config := range integration.Configs {
			configs[j] = ecommerceClient.IntegrationConfigResponse{
				IntegrationConfigID: config.IntegrationConfigID,
				Key:                 config.Key,
				Value:               config.Value,
			}
		}

		result[i] = &ecommerceClient.IntegrationResponse{
			IntegrationID: integration.IntegrationID,
			PosID:         integration.PosID,
			Name:          integration.Name,
			Type:          integration.Type,
			Status:        string(integration.Status),
			LastSync:      integration.LastSync,
			CreatedAt:     integration.CreatedAt,
			Configs:       configs,
		}
	}

	return result, nil
}

func NewEcommerceCredentialsService(integrationService integrationService.IntegrationService) ecommerceClient.EcommerceCredentialsService {
	adapter := NewIntegrationServiceAdapter(integrationService)
	return ecommerceClient.NewEcommerceCredentialsService(adapter)
}
