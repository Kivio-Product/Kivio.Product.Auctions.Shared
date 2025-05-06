package service

import (
	"context"
	"fmt"
	"time"

	"github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/dto"
	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/integration"
	infraIntegration "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/integration"
	infraSheets "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/sheets"
	"github.com/google/uuid"
)

type IntegrationService interface {
	CreateIntegration(ctx context.Context, req *dto.CreateIntegrationRequest) (*dto.IntegrationResponse, error)
	GetIntegrationByID(ctx context.Context, id string) (*dto.IntegrationResponse, error)
	GetIntegrationsByPosID(ctx context.Context, posID string) ([]*dto.IntegrationResponse, error)
	UpdateIntegration(ctx context.Context, id string, req *dto.UpdateIntegrationRequest) (*dto.IntegrationResponse, error)
	DeleteIntegration(ctx context.Context, id string) error
	ConnectAndReadSheet(ctx context.Context, integrationID string, spreadsheetID string, readRange string) error
}

type integrationService struct {
	integrationRepo infraIntegration.IntegrationRepository
	googleSheetRepo infraSheets.GoogleSheetsRepository
}

func NewIntegrationService(repo infraIntegration.IntegrationRepository, gsRepo infraSheets.GoogleSheetsRepository) IntegrationService {
	return &integrationService{
		integrationRepo: repo,
		googleSheetRepo: gsRepo,
	}
}

func (s *integrationService) CreateIntegration(ctx context.Context, req *dto.CreateIntegrationRequest) (*dto.IntegrationResponse, error) {
	integration := req.ToDomainIntegration()

	integration.IntegrationID = uuid.New().String()
	integration.CreatedAt = time.Now()
	integration.LastSync = time.Now()

	err := s.integrationRepo.SaveIntegration(integration)
	if err != nil {
		return nil, fmt.Errorf("error saving integration: %w", err)
	}

	for i := range integration.Configs {
		integration.Configs[i].IntegrationID = integration.IntegrationID
		integration.Configs[i].IntegrationConfigID = uuid.New().String()
		err = s.integrationRepo.SaveIntegrationConfig(&integration.Configs[i])
		if err != nil {
			return nil, fmt.Errorf("error saving integration config: %w", err)
		}
	}

	return dto.ToIntegrationResponse(integration), nil
}

func (s *integrationService) GetIntegrationByID(ctx context.Context, id string) (*dto.IntegrationResponse, error) {
	integration, err := s.integrationRepo.GetIntegrationByID(id)
	if err != nil {
		return nil, fmt.Errorf("error getting integration: %w", err)
	}

	return dto.ToIntegrationResponse(integration), nil
}

func (s *integrationService) GetIntegrationsByPosID(ctx context.Context, posID string) ([]*dto.IntegrationResponse, error) {
	integrations, err := s.integrationRepo.GetIntegrationsByPosID(posID)
	if err != nil {
		return nil, fmt.Errorf("error getting integrations by posID: %w", err)
	}

	var responses []*dto.IntegrationResponse
	for _, integration := range integrations {
		responses = append(responses, dto.ToIntegrationResponse(integration))
	}

	return responses, nil
}

func (s *integrationService) UpdateIntegration(ctx context.Context, id string, req *dto.UpdateIntegrationRequest) (*dto.IntegrationResponse, error) {
	existingIntegration, err := s.integrationRepo.GetIntegrationByID(id)
	if err != nil {
		return nil, fmt.Errorf("error getting integration to update: %w", err)
	}

	updatedIntegration := req.UpdateDomainIntegration(existingIntegration)
	updatedIntegration.IntegrationID = id

	err = s.integrationRepo.UpdateIntegration(updatedIntegration)
	if err != nil {
		return nil, fmt.Errorf("error updating integration: %w", err)
	}

	err = s.integrationRepo.DeleteIntegrationConfigs(id)
	if err != nil {
		return nil, fmt.Errorf("error deleting existing configs: %w", err)
	}

	for i := range req.Configs {
		config := domain.IntegrationConfig{
			IntegrationID:       id,
			IntegrationConfigID: uuid.New().String(),
			Key:                 req.Configs[i].Key,
			Value:               req.Configs[i].Value,
		}
		err = s.integrationRepo.SaveIntegrationConfig(&config)
		if err != nil {
			return nil, fmt.Errorf("error saving updated config: %w", err)
		}
		updatedIntegration.Configs = append(updatedIntegration.Configs, config)
	}

	return dto.ToIntegrationResponse(updatedIntegration), nil
}

func (s *integrationService) DeleteIntegration(ctx context.Context, id string) error {
	err := s.integrationRepo.DeleteIntegration(id)
	if err != nil {
		return fmt.Errorf("error deleting integration: %w", err)
	}
	return nil
}

func (s *integrationService) ConnectAndReadSheet(ctx context.Context, integrationID string, spreadsheetID string, readRange string) error {
	integration, err := s.integrationRepo.GetIntegrationByID(integrationID)
	if err != nil {
		return fmt.Errorf("integration not found: %w", err)
	}

	fmt.Printf("Connecting to Spreadsheet ID: %s, Range: %s\n", spreadsheetID, readRange)
	err = s.googleSheetRepo.ConnectToSheet(spreadsheetID, readRange)
	if err != nil {
		return fmt.Errorf("error connecting to google sheet: %w", err)
	}

	integration.Status = domain.Active
	err = s.integrationRepo.UpdateIntegration(integration)
	if err != nil {
		return fmt.Errorf("error updating integration status: %w", err)
	}

	fmt.Println("Successfully connected to Google Sheet and updated integration status to Connected.")

	return nil
}
