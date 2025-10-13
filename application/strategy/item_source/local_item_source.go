package item_source

import (
	"context"
	"fmt"

	itemDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
	itemInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/item"
)

// LocalItemSource implementa ItemSourceStrategy para items locales almacenados en DynamoDB
type LocalItemSource struct {
	itemRepo itemInfrastructure.ItemRepository
}

// NewLocalItemSource crea una nueva instancia del strategy para items locales
func NewLocalItemSource(itemRepo itemInfrastructure.ItemRepository) *LocalItemSource {
	return &LocalItemSource{
		itemRepo: itemRepo,
	}
}

// GetItemByID obtiene un item local por su ID desde DynamoDB
func (s *LocalItemSource) GetItemByID(ctx context.Context, itemID string) (*itemDomain.Item, error) {
	item, err := s.itemRepo.GetItemById(ctx, itemID)
	if err != nil {
		return nil, fmt.Errorf("error getting local item %s: %w", itemID, err)
	}
	return item, nil
}

// GetItemsByPointOfSale obtiene todos los items locales de un punto de venta
func (s *LocalItemSource) GetItemsByPointOfSale(ctx context.Context, posID string) ([]itemDomain.Item, error) {
	items, err := s.itemRepo.GetItemsByPosId(ctx, posID)
	if err != nil {
		return nil, fmt.Errorf("error getting local items for POS %s: %w", posID, err)
	}
	return items, nil
}

// UpdateItemStock actualiza el stock de un item local
// Para items locales, esto puede no hacer nada o actualizar un campo de stock si existe
func (s *LocalItemSource) UpdateItemStock(ctx context.Context, itemID string, newStock int) error {
	// Los items locales no tienen stock directamente, el stock está en ItemSpecification
	// Este método podría implementarse si se agrega stock al dominio de Item
	fmt.Printf("[LocalItemSource] UpdateItemStock called for local item %s with stock %d (no-op for local items)\n", itemID, newStock)
	return nil
}

// GetSourceType retorna el tipo de fuente
func (s *LocalItemSource) GetSourceType() string {
	return "local"
}
