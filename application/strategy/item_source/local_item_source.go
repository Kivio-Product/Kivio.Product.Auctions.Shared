package item_source

import (
	"context"
	"fmt"

	itemDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
	itemInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/item"
)

type LocalItemSource struct {
	itemRepo itemInfrastructure.ItemRepository
}

func NewLocalItemSource(itemRepo itemInfrastructure.ItemRepository) *LocalItemSource {
	return &LocalItemSource{
		itemRepo: itemRepo,
	}
}

func (s *LocalItemSource) GetItemByID(ctx context.Context, itemID string) (*itemDomain.Item, error) {
	item, err := s.itemRepo.GetItemById(ctx, itemID)
	if err != nil {
		return nil, fmt.Errorf("error getting local item %s: %w", itemID, err)
	}
	return item, nil
}

func (s *LocalItemSource) GetItemsByPointOfSale(ctx context.Context, posID string) ([]itemDomain.Item, error) {
	items, err := s.itemRepo.GetItemsByPosId(posID, nil)
	if err != nil {
		return nil, fmt.Errorf("error getting local items for POS %s: %w", posID, err)
	}
	return items, nil
}

func (s *LocalItemSource) UpdateItemStock(ctx context.Context, itemID string, newStock int) error {
	fmt.Printf("[LocalItemSource] UpdateItemStock called for local item %s with stock %d (no-op for local items)\n", itemID, newStock)
	return nil
}

func (s *LocalItemSource) GetSourceType() string {
	return "local"
}
