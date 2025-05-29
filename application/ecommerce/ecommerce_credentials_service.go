package services

import (
	"context"
	"fmt"

	"github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/dto"
	service "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/integration"
)

type EcommerceCredentials struct {
	ApiURL  string
	ApiKey  string
	Context context.Context
}

type EcommerceCredentialsService interface {
	GetCredentials(ctx context.Context, posID string) (*EcommerceCredentials, error)
}

type ecommerceCredentialsService struct {
	integrationService service.IntegrationService
	ecommerceService   EcommerceService
}

func NewEcommerceCredentialsService(
	integrationService service.IntegrationService,
	ecommerceService EcommerceService,
) EcommerceCredentialsService {
	return &ecommerceCredentialsService{
		integrationService: integrationService,
		ecommerceService:   ecommerceService,
	}
}

func (s *ecommerceCredentialsService) GetCredentials(ctx context.Context, posID string) (*EcommerceCredentials, error) {
	integrations, err := s.integrationService.GetIntegrationsByPosID(ctx, posID)
	if err != nil {
		return nil, fmt.Errorf("error fetching integrations: %w", err)
	}

	var ecommerceIntegration *dto.IntegrationResponse
	for _, integ := range integrations {
		if integ.Type == "kivio_ecommerce" && integ.Status == "Active" {
			ecommerceIntegration = integ
			break
		}
	}

	if ecommerceIntegration == nil {
		return nil, fmt.Errorf("no active ecommerce integration found for posID: %s", posID)
	}

	var apiUrl, username, password string
	for _, cfg := range ecommerceIntegration.Configs {
		switch cfg.Key {
		case "apiUrl":
			apiUrl = cfg.Value
		case "username":
			username = cfg.Value
		case "password":
			password = cfg.Value
		}
	}

	if apiUrl == "" || username == "" || password == "" {
		return nil, fmt.Errorf("missing required ecommerce credentials")
	}

	tokenUrl := fmt.Sprintf("%s/token", apiUrl)
	apiKey, err := s.ecommerceService.GetApiKey(ctx, username, password, tokenUrl)
	if err != nil {
		return nil, fmt.Errorf("error getting API key: %w", err)
	}

	return &EcommerceCredentials{
		ApiURL:  apiUrl,
		ApiKey:  apiKey,
		Context: ctx,
	}, nil
}
