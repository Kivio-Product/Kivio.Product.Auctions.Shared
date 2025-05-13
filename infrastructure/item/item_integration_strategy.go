package infrastructure

import (
	"fmt"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
	integrationRepository "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/integration"
)

type ItemIntegrationStrategy interface {
	GetItems(pointOfSaleId string) ([]domain.Item, error)
	GetItemById(itemId string, pointOfSaleId string) (*domain.Item, error)
}

type GoogleSheetsStrategy struct {
	googleSheetsRepository integrationRepository.GoogleSheetsRepository
	integrationRepository  integrationRepository.IntegrationRepository
}

func NewGoogleSheetsStrategy(googleSheetsRepo integrationRepository.GoogleSheetsRepository, integrationRepo integrationRepository.IntegrationRepository) *GoogleSheetsStrategy {
	return &GoogleSheetsStrategy{
		googleSheetsRepository: googleSheetsRepo,
		integrationRepository:  integrationRepo,
	}
}

func (s *GoogleSheetsStrategy) GetItems(pointOfSaleId string) ([]domain.Item, error) {
	integrations, err := s.integrationRepository.GetIntegrationsByPosID(pointOfSaleId)
	if err != nil {
		return nil, err
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
		return nil, nil
	}

	sheetData, err := s.googleSheetsRepository.GetSheetData(spreadsheetId, readRange)
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
					ItemId:        itemId,
					Name:          name,
					Description:   description,
					Source:        "google sheets",
					PointOfSaleId: pointOfSaleId,
					ExternalId:    itemId,
				}
				items = append(items, item)
			}
		}
	}

	return items, nil
}

func (s *GoogleSheetsStrategy) GetItemById(itemId string, pointOfSaleId string) (*domain.Item, error) {
	integrations, err := s.integrationRepository.GetIntegrationsByPosID(pointOfSaleId)
	if err != nil {
		return nil, err
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
		return nil, nil
	}

	sheetData, err := s.googleSheetsRepository.GetSheetData(spreadsheetId, readRange)
	if err != nil {
		return nil, err
	}

	for i, row := range sheetData.Values {
		if i == 0 {
			continue
		}

		if len(row) > 2 {
			rowItemId, ok1 := row[0].(string)
			if ok1 && rowItemId == itemId {
				name, ok2 := row[2].(string)
				description := ""
				if len(row) > 3 {
					description, _ = row[3].(string)
				}

				if ok2 {
					return &domain.Item{
						ItemId:        itemId,
						Name:          name,
						Description:   description,
						Source:        "google sheets",
						PointOfSaleId: pointOfSaleId,
						ExternalId:    itemId,
					}, nil
				}
			}
		}
	}

	return nil, nil
}

type EcommerceStrategy struct {
	ecommerceRepository   integrationRepository.EcommerceRepository
	integrationRepository integrationRepository.IntegrationRepository
}

func NewEcommerceStrategy(ecommerceRepo integrationRepository.EcommerceRepository, integrationRepo integrationRepository.IntegrationRepository) *EcommerceStrategy {
	return &EcommerceStrategy{
		ecommerceRepository:   ecommerceRepo,
		integrationRepository: integrationRepo,
	}
}

func (s *EcommerceStrategy) GetItems(pointOfSaleId string) ([]domain.Item, error) {
	integrations, err := s.integrationRepository.GetIntegrationsByPosID(pointOfSaleId)
	if err != nil {
		return nil, err
	}

	var baseUrl, username, password string
	for _, integration := range integrations {
		for _, config := range integration.Configs {
			switch config.Key {
			case "apiUrl":
				baseUrl = config.Value
			case "username":
				username = config.Value
			case "password":
				password = config.Value
			}
		}
	}

	if baseUrl == "" || username == "" || password == "" {
		return nil, fmt.Errorf("missing integration configuration for pointOfSaleId: %s", pointOfSaleId)
	}

	apiKey, err := s.ecommerceRepository.GetApiKey(username, password, fmt.Sprintf("%s/token", baseUrl))
	if err != nil {
		return nil, fmt.Errorf("failed to get API key: %w", err)
	}

	return s.ecommerceRepository.GetItems(baseUrl, apiKey)
}

func (s *EcommerceStrategy) GetItemById(itemId string, pointOfSaleId string) (*domain.Item, error) {
	integrations, err := s.integrationRepository.GetIntegrationsByPosID(pointOfSaleId)
	if err != nil {
		return nil, err
	}

	var baseUrl, username, password string
	for _, integration := range integrations {
		for _, config := range integration.Configs {
			switch config.Key {
			case "apiUrl":
				baseUrl = config.Value
			case "username":
				username = config.Value
			case "password":
				password = config.Value
			}
		}
	}

	if baseUrl == "" || username == "" || password == "" {
		return nil, fmt.Errorf("missing integration configuration for pointOfSaleId: %s", pointOfSaleId)
	}

	apiKey, err := s.ecommerceRepository.GetApiKey(username, password, fmt.Sprintf("%s/token", baseUrl))
	if err != nil {
		return nil, fmt.Errorf("failed to get API key: %w", err)
	}

	return s.ecommerceRepository.GetItemByID(baseUrl, apiKey, itemId)
}
