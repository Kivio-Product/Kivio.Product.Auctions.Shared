package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	ecommerceService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/ecommerce"
	itemSpecService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/item_specification"
	offerService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/offer"
	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
	integrationInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/integration"
	itemInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/item"
	itemSpecInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/item_specification"
)

type ItemService interface {
	CreateItem(ctx context.Context, name, description, externalId, pointOfSaleId, url string) (*domain.Item, error)
	GetItems() ([]domain.Item, error)
	GetItemById(ctx context.Context, id string) (*domain.Item, error)
	GetItemBySpecId(ctx context.Context, specId string) (*domain.Item, error)
	UpdateItem(ctx context.Context, id, name, description, externalId, pointOfSaleId, url string) error
	DeleteItemById(ctx context.Context, id string) error
	GetItemsByPosId(ctx context.Context, id string) ([]domain.Item, error)
	GetItemsByUserId(ctx context.Context, id string) ([]domain.Item, error)
}

type itemService struct {
	repo                  itemInfrastructure.ItemRepository
	integrationRepository integrationInfrastructure.IntegrationRepository
	itemFactory           domain.ItemFactory
	itemSpecService       itemSpecService.ItemSpecificationService
	offerService          offerService.IOfferService
	itemSpecRepo          itemSpecInfrastructure.ItemSpecificationRepository
	ecommerceCredSvc      ecommerceService.EcommerceCredentialsService
	ecommerceSvc          ecommerceService.EcommerceService
}

func NewItemService(
	repo itemInfrastructure.ItemRepository,
	itemFactory domain.ItemFactory,
	integrationRepository integrationInfrastructure.IntegrationRepository,
	itemSpecService itemSpecService.ItemSpecificationService,
	offerService offerService.IOfferService,
	itemSpecRepo itemSpecInfrastructure.ItemSpecificationRepository,
	ecommerceCredSvc ecommerceService.EcommerceCredentialsService,
	ecommerceSvc ecommerceService.EcommerceService,
) ItemService {
	return &itemService{
		repo:                  repo,
		itemFactory:           itemFactory,
		integrationRepository: integrationRepository,
		itemSpecService:       itemSpecService,
		offerService:          offerService,
		itemSpecRepo:          itemSpecRepo,
		ecommerceCredSvc:      ecommerceCredSvc,
		ecommerceSvc:          ecommerceSvc,
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

	var filteredItems []domain.Item
	for _, item := range items {
		if !strings.HasPrefix(item.ItemId, "kivio-ecommerce∼") {
			itemSpecs, err := s.itemSpecRepo.GetItemSpecByItem(item.ItemId, item.PointOfSaleId)
			if err != nil {
				continue
			}

			hasStock := false
			for _, spec := range itemSpecs {
				if spec.Availability > 0 {
					hasStock = true
					break
				}
			}

			if hasStock {
				filteredItems = append(filteredItems, item)
			}
		} else {
			credentials, err := s.ecommerceCredSvc.GetCredentials(context.Background(), item.PointOfSaleId)
			if err != nil {
				continue
			}

			itemId := strings.TrimPrefix(item.ItemId, "kivio-ecommerce∼")
			itemRaw, err := s.ecommerceSvc.GetItemByIDRaw(context.Background(), itemId, credentials.ApiURL, credentials.ApiKey)
			if err != nil {
				continue
			}

			var extResp struct {
				Products []struct {
					StockQuantity int64 `json:"stock_quantity"`
				} `json:"products"`
			}
			if err := json.Unmarshal(itemRaw, &extResp); err == nil && len(extResp.Products) > 0 {
				if extResp.Products[0].StockQuantity > 0 {
					filteredItems = append(filteredItems, item)
				}
			}
		}
	}

	return filteredItems, nil
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

func (s *itemService) GetItemBySpecId(ctx context.Context, id string) (*domain.Item, error) {
	var item *domain.Item

	itemSpec, err := s.itemSpecRepo.GetById(ctx, id)
	if err != nil {
		return nil, err
	}

	if itemSpec.IsExternal {
		credentials, err := s.ecommerceCredSvc.GetCredentials(ctx, itemSpec.PointOfSaleId)
		if err != nil {
			return nil, err
		}

		itemId := strings.TrimPrefix(itemSpec.ItemId, "kivio-ecommerce∼")
		item, err = s.ecommerceSvc.GetItemByID(ctx, credentials.ApiURL, credentials.ApiKey, itemId)
		if err != nil {
			return nil, err
		}
	} else {
		item, err = s.repo.GetItemById(ctx, itemSpec.ItemId)
		if err != nil {
			return nil, err
		}
	}

	return item, nil
}

func (s *itemService) GetItemsByPosId(ctx context.Context, id string) ([]domain.Item, error) {
	items, err := s.repo.GetItemsByPosId(id)
	if err != nil {
		return nil, err
	}

	for i := range items {
		items[i].Source = "local"
	}

	return items, nil
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
	item, err := s.repo.GetItemById(ctx, id)
	if err != nil {
		return err
	}
	if item.PointOfSaleId == "" {
		return fmt.Errorf("el item no tiene PointOfSaleId, no se puede continuar")
	}

	itemSpecs, err := s.itemSpecService.GetItemSpecByItemId(ctx, id, item.PointOfSaleId)
	if err != nil {
		return err
	}

	offerIdSet := make(map[string]struct{})
	for _, spec := range itemSpecs {
		if spec.OfferId != "" {
			offerIdSet[spec.OfferId] = struct{}{}
		}
	}

	for offerId := range offerIdSet {
		offer, err := s.offerService.GetOfferById(ctx, offerId)
		if err != nil {
			return err
		}
		if offer.State == "Created" || offer.State == "Offered" {
			return fmt.Errorf("no se puede eliminar el item porque tiene ofertas activas asociadas (OfferId: %s)", offerId)
		}
	}

	return s.repo.DeleteItem(ctx, id)
}
