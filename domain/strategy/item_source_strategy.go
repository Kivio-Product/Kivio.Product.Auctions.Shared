package strategy

import (
	"context"

	itemDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
)

// ItemSourceStrategy define la interfaz para obtener items de diferentes fuentes (local, ecommerce, etc.)
type ItemSourceStrategy interface {
	// GetItemByID obtiene un item por su ID
	GetItemByID(ctx context.Context, itemID string) (*itemDomain.Item, error)

	// GetItemsByPointOfSale obtiene todos los items de un punto de venta
	GetItemsByPointOfSale(ctx context.Context, posID string) ([]itemDomain.Item, error)

	// UpdateItemStock actualiza el stock de un item
	UpdateItemStock(ctx context.Context, itemID string, newStock int) error

	// GetSourceType retorna el tipo de fuente (local, ecommerce, etc.)
	GetSourceType() string
}
