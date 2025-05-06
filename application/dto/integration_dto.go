package dto

import (
	"time"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/integration"
)

type CreateIntegrationRequest struct {
	PosID   string                           `json:"posId"`
	Type    string                           `json:"type"`
	Name    string                           `json:"name"`
	Configs []CreateIntegrationConfigRequest `json:"configs"`
}

type CreateIntegrationConfigRequest struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type UpdateIntegrationRequest struct {
	PosID   string                           `json:"posId,omitempty"`
	Type    string                           `json:"type,omitempty"`
	Status  string                           `json:"status,omitempty"`
	Configs []CreateIntegrationConfigRequest `json:"configs,omitempty"`
}

type IntegrationResponse struct {
	IntegrationID string                      `json:"integrationId"`
	PosID         string                      `json:"posId"`
	Name          string                      `json:"name"`
	Type          string                      `json:"type"`
	Status        domain.IntegrationStatus    `json:"status"`
	LastSync      time.Time                   `json:"lastSync"`
	CreatedAt     time.Time                   `json:"createdAt"`
	Configs       []IntegrationConfigResponse `json:"configs"`
}

type IntegrationConfigResponse struct {
	IntegrationConfigID string `json:"integrationConfigId"`
	Key                 string `json:"key"`
	Value               string `json:"value"`
}

func (r *CreateIntegrationRequest) ToDomainIntegration() *domain.Integration {
	configs := make([]domain.IntegrationConfig, len(r.Configs))
	for i, cfg := range r.Configs {
		configs[i] = domain.IntegrationConfig{
			Key:   cfg.Key,
			Value: cfg.Value,
		}
	}
	return &domain.Integration{
		PosID:   r.PosID,
		Name:    r.Name,
		Type:    r.Type,
		Status:  domain.Inactive,
		Configs: configs,
	}
}

func (r *UpdateIntegrationRequest) UpdateDomainIntegration(existing *domain.Integration) *domain.Integration {
	updated := *existing

	if r.PosID != "" {
		updated.PosID = r.PosID
	}
	if r.Type != "" {
		updated.Type = r.Type
	}
	if r.Status != "" {
		updated.Status = domain.IntegrationStatus(r.Status)
	}

	return &updated
}

func ToIntegrationResponse(integration *domain.Integration) *IntegrationResponse {
	configs := make([]IntegrationConfigResponse, len(integration.Configs))
	for i, cfg := range integration.Configs {
		configs[i] = IntegrationConfigResponse{
			IntegrationConfigID: cfg.IntegrationConfigID,
			Key:                 cfg.Key,
			Value:               cfg.Value,
		}
	}
	return &IntegrationResponse{
		IntegrationID: integration.IntegrationID,
		Name:          integration.Name,
		PosID:         integration.PosID,
		Type:          integration.Type,
		Status:        integration.Status,
		LastSync:      integration.LastSync,
		CreatedAt:     integration.CreatedAt,
		Configs:       configs,
	}
}
