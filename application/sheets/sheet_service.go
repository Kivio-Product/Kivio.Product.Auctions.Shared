package services

import (
	"fmt"

	sheetsDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/sheets"
	integrationInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/integration"
)

type SheetService interface {
	FetchSheetData(pointOfSaleId string) (sheetsDomain.SheetData, error)
}

type sheetService struct {
	repo                  integrationInfrastructure.GoogleSheetsRepository
	integrationRepository integrationInfrastructure.IntegrationRepository
}

func NewSheetService(repo integrationInfrastructure.GoogleSheetsRepository, integrationRepository integrationInfrastructure.IntegrationRepository) SheetService {
	return &sheetService{repo: repo, integrationRepository: integrationRepository}
}

func (s *sheetService) FetchSheetData(pointOfSaleId string) (sheetsDomain.SheetData, error) {
	integrations, err := s.integrationRepository.GetIntegrationsByPosID(pointOfSaleId)
	if err != nil {
		return sheetsDomain.SheetData{}, err
	}

	var spreadsheetId, readRange string

	for _, integration := range integrations {
		for _, config := range integration.Configs {
			if config.Key == "spreadsheetId" {
				spreadsheetId = config.Value
			} else if config.Key == "readRange" {
				readRange = config.Value
			}
		}
	}

	if spreadsheetId == "" || readRange == "" {
		return sheetsDomain.SheetData{}, fmt.Errorf("missing Google Sheets configuration for pointOfSaleId %s", pointOfSaleId)
	}
	return s.repo.GetSheetData(spreadsheetId, readRange)
}
