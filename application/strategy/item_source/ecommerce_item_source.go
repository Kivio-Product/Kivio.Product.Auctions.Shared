package item_source

import (
	"context"
	"fmt"
	"strings"

	ecommerceService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/ecommerce"
	itemDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
)

type EcommerceItemSource struct {
	ecommerceCredSvc ecommerceService.EcommerceCredentialsService
	ecommerceSvc     ecommerceService.EcommerceService
	posID            string // POS ID to use for this item source instance
}

func NewEcommerceItemSource(
	ecommerceCredSvc ecommerceService.EcommerceCredentialsService,
	ecommerceSvc ecommerceService.EcommerceService,
	posID string,
) *EcommerceItemSource {
	return &EcommerceItemSource{
		ecommerceCredSvc: ecommerceCredSvc,
		ecommerceSvc:     ecommerceSvc,
		posID:            posID,
	}
}

func (s *EcommerceItemSource) GetItemByID(ctx context.Context, itemID string) (*itemDomain.Item, error) {
	if s.posID == "" {
		return nil, fmt.Errorf("GetItemByID requires posID to be set during initialization - use GetItemByIDWithPosID instead")
	}

	credentials, err := s.ecommerceCredSvc.GetCredentials(ctx, s.posID)
	if err != nil {
		return nil, fmt.Errorf("error getting ecommerce credentials for POS %s: %w", s.posID, err)
	}

	cleanItemID := strings.TrimPrefix(itemID, "kivio-ecommerce~")

	item, err := s.ecommerceSvc.GetItemByID(ctx, cleanItemID, credentials.ApiURL, credentials.ApiKey)
	if err != nil {
		return nil, fmt.Errorf("error getting ecommerce item %s: %w", cleanItemID, err)
	}

	return item, nil
}

func (s *EcommerceItemSource) GetItemByIDWithPosID(ctx context.Context, itemID string, posID string) (*itemDomain.Item, error) {
	credentials, err := s.ecommerceCredSvc.GetCredentials(ctx, posID)
	if err != nil {
		return nil, fmt.Errorf("error getting ecommerce credentials for POS %s: %w", posID, err)
	}

	cleanItemID := strings.TrimPrefix(itemID, "kivio-ecommerce~")

	item, err := s.ecommerceSvc.GetItemByID(ctx, cleanItemID, credentials.ApiURL, credentials.ApiKey)
	if err != nil {
		return nil, fmt.Errorf("error getting ecommerce item %s: %w", cleanItemID, err)
	}

	return item, nil
}

func (s *EcommerceItemSource) GetItemsByPointOfSale(ctx context.Context, posID string) ([]itemDomain.Item, error) {
	credentials, err := s.ecommerceCredSvc.GetCredentials(ctx, posID)
	if err != nil {
		return nil, fmt.Errorf("error getting ecommerce credentials for POS %s: %w", posID, err)
	}

	items, err := s.ecommerceSvc.GetItems(ctx, credentials.ApiURL, credentials.ApiKey, 1, 100)
	if err != nil {
		return nil, fmt.Errorf("error getting ecommerce items for POS %s: %w", posID, err)
	}

	return items, nil
}

func (s *EcommerceItemSource) UpdateItemStock(ctx context.Context, itemID string, newStock int) error {
	if s.posID == "" {
		return fmt.Errorf("UpdateItemStock requires posID to be set during initialization - use UpdateItemStockWithPosID instead")
	}

	credentials, err := s.ecommerceCredSvc.GetCredentials(ctx, s.posID)
	if err != nil {
		return fmt.Errorf("error getting ecommerce credentials for POS %s: %w", s.posID, err)
	}

	cleanItemID := strings.TrimPrefix(itemID, "kivio-ecommerce~")

	err = s.ecommerceSvc.UpdateItemStock(ctx, credentials.ApiURL, credentials.ApiKey, cleanItemID, newStock)
	if err != nil {
		return fmt.Errorf("error updating ecommerce item stock %s: %w", cleanItemID, err)
	}

	return nil
}

func (s *EcommerceItemSource) UpdateItemStockWithPosID(ctx context.Context, itemID string, posID string, newStock int) error {
	credentials, err := s.ecommerceCredSvc.GetCredentials(ctx, posID)
	if err != nil {
		return fmt.Errorf("error getting ecommerce credentials for POS %s: %w", posID, err)
	}

	cleanItemID := strings.TrimPrefix(itemID, "kivio-ecommerce~")

	err = s.ecommerceSvc.UpdateItemStock(ctx, credentials.ApiURL, credentials.ApiKey, cleanItemID, newStock)
	if err != nil {
		return fmt.Errorf("error updating ecommerce item stock %s: %w", cleanItemID, err)
	}

	return nil
}

func (s *EcommerceItemSource) GetSourceType() string {
	return "kivio_ecommerce"
}
