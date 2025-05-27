package services

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
	integrationInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/integration"
	itemInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/item"
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
	repo                   itemInfrastructure.ItemRepository
	integrationRepository  integrationInfrastructure.IntegrationRepository
	itemFactory            domain.ItemFactory
	itemIntegrationFactory *itemInfrastructure.ItemIntegrationFactory
}

func NewItemService(
	repo itemInfrastructure.ItemRepository,
	itemFactory domain.ItemFactory,
	integrationRepository integrationInfrastructure.IntegrationRepository,
	itemIntegrationFactory *itemInfrastructure.ItemIntegrationFactory,
) ItemService {
	return &itemService{
		repo:                   repo,
		itemFactory:            itemFactory,
		integrationRepository:  integrationRepository,
		itemIntegrationFactory: itemIntegrationFactory,
	}
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

	for _, integration := range integrations {
		strategy, err := s.itemIntegrationFactory.GetStrategy(integration.Type)
		if err != nil {
			continue
		}

		integrationItems, err := strategy.GetItems(id)
		if err != nil {
			continue
		}

		items = append(items, integrationItems...)
	}

	return items, nil
}

func (s *itemService) GetExternalItemById(ctx context.Context, itemId string, pointOfSaleId string) (*domain.Item, error) {
	var cleanedItemId string

	decodedId, err := url.QueryUnescape(itemId)
	if err != nil {
		return nil, err
	}

	if strings.Contains(decodedId, "∼") {
		parts := strings.Split(decodedId, "∼")
		cleanedItemId = parts[len(parts)-1]
	} else {
		cleanedItemId = decodedId
	}

	integrations, err := s.integrationRepository.GetIntegrationsByPosID(pointOfSaleId)
	if err != nil {
		return nil, err
	}

	for _, integration := range integrations {
		strategy, err := s.itemIntegrationFactory.GetStrategy(integration.Type)
		if err != nil {
			continue
		}

		item, err := strategy.GetItemById(cleanedItemId, pointOfSaleId)
		if err != nil {
			continue
		}

		if item != nil {
			return item, nil
		}
	}

	return nil, fmt.Errorf("item with id %s not found in any integration", itemId)
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
