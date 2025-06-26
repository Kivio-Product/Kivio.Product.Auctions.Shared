package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	ecommerceService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/ecommerce"
	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item_specification"
	itemSpecInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/item_specification"
)

type ItemSpecificationService interface {
	Create(ctx context.Context, currency, offerId, itemId, pointOfSaleId string, amount, availability int64, expireAt time.Time, isExternal bool) (*domain.ItemSpecification, error)
	Get() ([]domain.ItemSpecification, error)
	GetById(ctx context.Context, id string) (*domain.ItemSpecification, error)
	Update(ctx context.Context, id, currency, offerId, itemId, pointOfSaleId string, amount, availability int64, expireAt time.Time) error
	Delete(ctx context.Context, id string) error
	GetItemSpecByOfferId(ctx context.Context, id string, pointOfSaleId string) ([]domain.ItemSpecification, error)
	GetItemSpecByItemId(ctx context.Context, id string, pointOfSaleId string) ([]domain.ItemSpecification, error)
}

type itemSpecificationService struct {
	repo                     itemSpecInfrastructure.ItemSpecificationRepository
	itemSpecificationFactory domain.ItemSpecificationFactory
	ecommerceCredSvc         ecommerceService.EcommerceCredentialsService
	ecommerceSvc             ecommerceService.EcommerceService
}

func NewItemSpecificationService(
	repo itemSpecInfrastructure.ItemSpecificationRepository,
	itemSpecificationFactory domain.ItemSpecificationFactory,
	ecommerceCredSvc ecommerceService.EcommerceCredentialsService,
	ecommerceSvc ecommerceService.EcommerceService,
) ItemSpecificationService {
	return &itemSpecificationService{
		repo:                     repo,
		itemSpecificationFactory: itemSpecificationFactory,
		ecommerceCredSvc:         ecommerceCredSvc,
		ecommerceSvc:             ecommerceSvc,
	}
}

func (s *itemSpecificationService) Create(ctx context.Context, currency, offerId, itemId, pointOfSaleId string, amount, availability int64, expireAt time.Time, isExternal bool) (*domain.ItemSpecification, error) {
	itemSpecification, err := s.itemSpecificationFactory.CreateItemSpecification(currency, offerId, itemId, pointOfSaleId, amount, availability, expireAt, isExternal)

	if err != nil {
		return &domain.ItemSpecification{}, err
	}

	err = s.repo.Save(ctx, itemSpecification)

	if err != nil {
		return &domain.ItemSpecification{}, err
	}

	return itemSpecification, nil
}

func (s *itemSpecificationService) Get() ([]domain.ItemSpecification, error) {
	items, err := s.repo.Get()
	if err != nil {
		return nil, err
	}
	return items, nil
}

func (s *itemSpecificationService) GetById(ctx context.Context, id string) (*domain.ItemSpecification, error) {
	items, err := s.repo.GetById(ctx, id)
	if err != nil {
		return &domain.ItemSpecification{}, err
	}
	return items, nil
}

func (s *itemSpecificationService) Update(ctx context.Context, id, currency, offerId, itemId, pointOfSaleId string, amount, availability int64, expireAt time.Time) error {
	item, err := s.repo.GetById(ctx, id)
	err = item.Update(currency, offerId, itemId, pointOfSaleId, amount, availability, expireAt)
	if err != nil {
		return err
	}
	return s.repo.Save(ctx, item)
}

func (s *itemSpecificationService) Delete(ctx context.Context, id string) error {
	err := s.repo.Delete(ctx, id)
	return err
}

func (s *itemSpecificationService) GetItemSpecByOfferId(ctx context.Context, id string, pointOfSaleId string) ([]domain.ItemSpecification, error) {
	itemsSpec, err := s.repo.GetItemSpecByOffer(id, pointOfSaleId)

	fmt.Println("itemSpecification", itemsSpec)
	if err != nil {
		return nil, err
	}
	return itemsSpec, nil
}

func (s *itemSpecificationService) GetItemSpecByItemId(ctx context.Context, id string, pointOfSaleId string) ([]domain.ItemSpecification, error) {
	itemSpecs, err := s.repo.GetItemSpecByItem(id, pointOfSaleId)
	if err != nil {
		return nil, err
	}

	for i, spec := range itemSpecs {
		if spec.IsExternal {
			credentials, err := s.ecommerceCredSvc.GetCredentials(ctx, pointOfSaleId)
			if err != nil {
				continue
			}
			itemId := strings.TrimPrefix(spec.ItemId, "kivio-ecommerce∼")
			itemRaw, err := s.ecommerceSvc.GetItemByIDRaw(ctx, itemId, credentials.ApiURL, credentials.ApiKey)
			if err == nil && itemRaw != nil {
				type externalProductResponse struct {
					Products []struct {
						StockQuantity int64 `json:"stock_quantity"`
					} `json:"products"`
				}
				var extResp externalProductResponse
				if err := json.Unmarshal(itemRaw, &extResp); err == nil && len(extResp.Products) > 0 {
					itemSpecs[i].Availability = extResp.Products[0].StockQuantity
				}
			}
		}
	}
	return itemSpecs, nil
}
