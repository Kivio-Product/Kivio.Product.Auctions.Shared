package item_source

import (
	"context"
	"fmt"
	"strings"

	ecommerceService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/ecommerce"
	itemDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
)

// EcommerceItemSource implementa ItemSourceStrategy para items de ecommerce
type EcommerceItemSource struct {
	ecommerceCredSvc ecommerceService.EcommerceCredentialsService
	ecommerceSvc     ecommerceService.EcommerceService
}

// NewEcommerceItemSource crea una nueva instancia del strategy para items de ecommerce
func NewEcommerceItemSource(
	ecommerceCredSvc ecommerceService.EcommerceCredentialsService,
	ecommerceSvc ecommerceService.EcommerceService,
) *EcommerceItemSource {
	return &EcommerceItemSource{
		ecommerceCredSvc: ecommerceCredSvc,
		ecommerceSvc:     ecommerceSvc,
	}
}

// GetItemByID obtiene un item de ecommerce por su ID
// El itemID para ecommerce viene con el prefijo "kivio-ecommerce~"
func (s *EcommerceItemSource) GetItemByID(ctx context.Context, itemID string) (*itemDomain.Item, error) {
	// Obtener credenciales (necesitamos el posID, que no tenemos aquí)
	// Este método necesita mejorarse para recibir posID o almacenar contexto
	return nil, fmt.Errorf("GetItemByID not fully implemented for ecommerce - use GetItemByIDWithPosID instead")
}

// GetItemByIDWithPosID obtiene un item de ecommerce por su ID y posID
func (s *EcommerceItemSource) GetItemByIDWithPosID(ctx context.Context, itemID string, posID string) (*itemDomain.Item, error) {
	credentials, err := s.ecommerceCredSvc.GetCredentials(ctx, posID)
	if err != nil {
		return nil, fmt.Errorf("error getting ecommerce credentials for POS %s: %w", posID, err)
	}

	// Remover el prefijo si existe
	cleanItemID := strings.TrimPrefix(itemID, "kivio-ecommerce~")

	item, err := s.ecommerceSvc.GetItemByID(ctx, cleanItemID, credentials.ApiURL, credentials.ApiKey)
	if err != nil {
		return nil, fmt.Errorf("error getting ecommerce item %s: %w", cleanItemID, err)
	}

	return item, nil
}

// GetItemsByPointOfSale obtiene todos los items de ecommerce para un punto de venta
func (s *EcommerceItemSource) GetItemsByPointOfSale(ctx context.Context, posID string) ([]itemDomain.Item, error) {
	credentials, err := s.ecommerceCredSvc.GetCredentials(ctx, posID)
	if err != nil {
		return nil, fmt.Errorf("error getting ecommerce credentials for POS %s: %w", posID, err)
	}

	// Obtener items del ecommerce (página 1, límite 100 por ejemplo)
	items, err := s.ecommerceSvc.GetItems(ctx, credentials.ApiURL, credentials.ApiKey, 1, 100)
	if err != nil {
		return nil, fmt.Errorf("error getting ecommerce items for POS %s: %w", posID, err)
	}

	return items, nil
}

// UpdateItemStock actualiza el stock de un item en el ecommerce
func (s *EcommerceItemSource) UpdateItemStock(ctx context.Context, itemID string, newStock int) error {
	// Para actualizar stock necesitamos posID
	return fmt.Errorf("UpdateItemStock not fully implemented for ecommerce - use UpdateItemStockWithPosID instead")
}

// UpdateItemStockWithPosID actualiza el stock de un item en el ecommerce
func (s *EcommerceItemSource) UpdateItemStockWithPosID(ctx context.Context, itemID string, posID string, newStock int) error {
	credentials, err := s.ecommerceCredSvc.GetCredentials(ctx, posID)
	if err != nil {
		return fmt.Errorf("error getting ecommerce credentials for POS %s: %w", posID, err)
	}

	// Remover el prefijo si existe
	cleanItemID := strings.TrimPrefix(itemID, "kivio-ecommerce~")

	err = s.ecommerceSvc.UpdateItemStock(ctx, credentials.ApiURL, credentials.ApiKey, cleanItemID, newStock)
	if err != nil {
		return fmt.Errorf("error updating ecommerce item stock %s: %w", cleanItemID, err)
	}

	return nil
}

// GetSourceType retorna el tipo de fuente
func (s *EcommerceItemSource) GetSourceType() string {
	return "ecommerce"
}
