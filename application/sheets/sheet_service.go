package services

import (
	"fmt"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
	sheetsDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/sheets"
	integrationInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/integration"
)

type SheetService interface {
	FetchSheetData(pointOfSaleId string) (sheetsDomain.SheetData, error)
	GetItemsFromSheet(pointOfSaleId string) ([]domain.Item, error)
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

func (s *sheetService) GetItemsFromSheet(pointOfSaleId string) ([]domain.Item, error) {
	sheetData, err := s.FetchSheetData(pointOfSaleId)
	if err != nil {
		return nil, err
	}

	var items []domain.Item
	for i, row := range sheetData.Values {
		if i == 0 {
			continue
		}

		if len(row) > 2 {
			itemId, ok1 := row[0].(string)
			name, ok2 := row[2].(string)
			description := ""
			if len(row) > 3 {
				description, _ = row[3].(string)
			}

			if ok1 && ok2 {
				item := domain.Item{
					ItemId:        fmt.Sprintf("google-sheets∼%s", itemId),
					Name:          name,
					Description:   description,
					Source:        "google sheets",
					PointOfSaleId: pointOfSaleId,
					ExternalId:    fmt.Sprintf("google-sheets∼%s", itemId),
				}
				items = append(items, item)
			}
		}
	}

	return items, nil
}
