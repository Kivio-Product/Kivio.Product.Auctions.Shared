package services

import (
	"context"
	"fmt"

	sharedinfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Infrastructure.Shared"
	"github.com/Kivio-Product/Kivio.Product.Auctions.Services/internal/domain"
	"github.com/Kivio-Product/Kivio.Product.Auctions.Services/internal/infrastructure"
)

type ItemService interface {
	CreateItem(ctx context.Context, name, description, externalId, pointOfSaleId, url string) (*domain.Item, error)
	GetItems() ([]domain.Item, error)
	GetItemById(ctx context.Context, id string) (*domain.Item, error)
	GetExternalItemById(ctx context.Context, itemId string, pointOfSaleId string) (*domain.Item, error)
	UpdateItem(ctx context.Context, id, name, description, externalId, pointOfSaleId, url string) error
	DeleteItemById(ctx context.Context, id string) error
	GetItemsByPosId(ctx context.Context, id string) ([]domain.Item, error)
	GetItemsByUserId(ctx context.Context, id string) ([]domain.Item, error)
}

type itemService struct {
	repo                   infrastructure.ItemRepository
	integrationRepository  sharedinfrastructure.IntegrationRepository
	googleSheetsRepository sharedinfrastructure.GoogleSheetsRepository
	itemFactory            domain.ItemFactory
}

func NewItemService(repo infrastructure.ItemRepository, itemFactory domain.ItemFactory, integrationRepository sharedinfrastructure.IntegrationRepository,
	googleSheetsRepository sharedinfrastructure.GoogleSheetsRepository) ItemService {
	return &itemService{repo: repo, itemFactory: itemFactory, integrationRepository: integrationRepository, googleSheetsRepository: googleSheetsRepository}
}

func (s *itemService) CreateItem(ctx context.Context, name, description, externalId, pointOfSaleId, url string) (*domain.Item, error) {
	item, err := s.itemFactory.CreateItem(name, description, externalId, pointOfSaleId, url)

	if err != nil {
		return &domain.Item{}, err
	}

	err = s.repo.SaveItem(ctx, item)

	if err != nil {
		return &domain.Item{}, err
	}

	return item, nil
}

func (s *itemService) GetItems() ([]domain.Item, error) {
	items, err := s.repo.GetAllItems()
	if err != nil {
		return nil, err
	}
	return items, nil
}

func (s *itemService) GetItemsByUserId(ctx context.Context, id string) ([]domain.Item, error) {
	items, err := s.repo.GetItemsByUserID(id)
	if err != nil {
		return nil, err
	}
	return items, nil
}

func (s *itemService) GetItemById(ctx context.Context, id string) (*domain.Item, error) {
	items, err := s.repo.GetItemById(ctx, id)
	if err != nil {
		return &domain.Item{}, err
	}
	return items, nil
}

func (s *itemService) GetItemsByPosId(ctx context.Context, id string) ([]domain.Item, error) {
	items, err := s.repo.GetItemsByPosId(id)
	if err != nil {
		return nil, err
	}

	for i := range items {
		items[i].Source = "local"
	}

	integrations, err := s.integrationRepository.GetIntegrationsByPosID(id)
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

	var sheetItems []domain.Item

	if spreadsheetId != "" && readRange != "" {
		sheetData, err := s.googleSheetsRepository.GetSheetData(spreadsheetId, readRange)
		if err != nil {
			return nil, fmt.Errorf("failed to get sheet data: %w", err)
		}

		if sheetData.Values == nil {
			return nil, fmt.Errorf("sheet data or values are nil")
		}

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
						PointOfSaleId: id,
						ExternalId:    itemId,
					}
					sheetItems = append(sheetItems, item)
				} else {
					fmt.Printf("invalid row data: %v\n", row)
				}
			}
		}
	}

	items = append(sheetItems, items...)

	return items, nil
}

func (s *itemService) GetExternalItemById(ctx context.Context, itemId string, pointOfSaleId string) (*domain.Item, error) {
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
		return nil, fmt.Errorf("missing Google Sheets configuration for pointOfSaleId %s", pointOfSaleId)
	}

	sheetData, err := s.googleSheetsRepository.GetSheetData(spreadsheetId, readRange)
	if err != nil {
		return nil, fmt.Errorf("failed to get sheet data: %w", err)
	}

	if sheetData.Values == nil {
		return nil, fmt.Errorf("sheet data or values are nil")
	}

	for i, row := range sheetData.Values {
		if i == 0 {
			continue // Skip header row
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

	return nil, fmt.Errorf("item with id %s not found in Google Sheets", itemId)
}

func (s *itemService) UpdateItem(ctx context.Context, id, name, description, externalId, pointOfSaleId, url string) error {
	item, err := s.repo.GetItemById(ctx, id)
	err = item.Update(name, description, externalId, pointOfSaleId, url)
	if err != nil {
		return err
	}
	return s.repo.SaveItem(ctx, item)
}

func (s *itemService) DeleteItemById(ctx context.Context, id string) error {
	err := s.repo.DeleteItem(ctx, id)
	return err
}
