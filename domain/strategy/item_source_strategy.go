package strategy

import (
	"context"

	itemDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
)

type ItemSourceStrategy interface {
	GetItemByID(ctx context.Context, itemID string) (*itemDomain.Item, error)
	GetItemsByPointOfSale(ctx context.Context, posID string) ([]itemDomain.Item, error)
	UpdateItemStock(ctx context.Context, itemID string, newStock int) error
	GetSourceType() string
}
