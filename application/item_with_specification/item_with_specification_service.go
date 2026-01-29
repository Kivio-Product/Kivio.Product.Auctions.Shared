package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	ecommerceService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/ecommerce"
	itemSpecService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/item_specification"
	strategyApplication "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/strategy"
	itemDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
	itemSpecDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item_specification"
	itemSpecInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/item_specification"
)

type ItemWithSpecification struct {
	Id                 string
	Amount             int64
	Currency           string
	ExpireAt           string
	OfferId            string
	ItemId             string
	Availability       int64
	State              string
	AllowMultipleItems bool
	MaxPricePercentage float64

	Item *itemDomain.Item
}

type ItemWithSpecificationService interface {
	GetItemsWithSpecificationsByOfferId(ctx context.Context, offerID string, pointOfSaleID string) ([]ItemWithSpecification, error)
}

type itemWithSpecificationService struct {
	itemSpecService   itemSpecService.ItemSpecificationService
	itemSourceFactory *strategyApplication.ItemSourceFactory
	ecommerceCredSvc  ecommerceService.EcommerceCredentialsService
	ecommerceSvc      ecommerceService.EcommerceService
	itemSpecRepo      itemSpecInfrastructure.ItemSpecificationRepository
}

func NewItemWithSpecificationService(
	itemSpecService itemSpecService.ItemSpecificationService,
	itemSourceFactory *strategyApplication.ItemSourceFactory,
	ecommerceCredSvc ecommerceService.EcommerceCredentialsService,
	ecommerceSvc ecommerceService.EcommerceService,
	itemSpecRepo itemSpecInfrastructure.ItemSpecificationRepository,
) ItemWithSpecificationService {
	return &itemWithSpecificationService{
		itemSpecService:   itemSpecService,
		itemSourceFactory: itemSourceFactory,
		ecommerceCredSvc:  ecommerceCredSvc,
		ecommerceSvc:      ecommerceSvc,
		itemSpecRepo:      itemSpecRepo,
	}
}

func (s *itemWithSpecificationService) GetItemsWithSpecificationsByOfferId(
	ctx context.Context,
	offerID string,
	pointOfSaleID string,
) ([]ItemWithSpecification, error) {
	itemSpecs, err := s.itemSpecService.GetItemSpecByOfferId(ctx, offerID, pointOfSaleID)
	if err != nil {
		return nil, fmt.Errorf("error fetching item specifications: %w", err)
	}

	var result []ItemWithSpecification

	for _, spec := range itemSpecs {
		source := string(spec.GetSource())

		strategy, err := s.itemSourceFactory.GetStrategyByItemSpec(ctx, source, pointOfSaleID)
		if err != nil {
			fmt.Printf("Warning: could not get item source strategy for item %s (source: %s): %v\n", spec.ItemId, source, err)
			continue
		}

		item, err := strategy.GetItemByID(ctx, spec.ItemId)
		if err != nil {
			fmt.Printf("Warning: could not retrieve item %s: %v\n", spec.ItemId, err)
			continue
		}

		if item == nil {
			continue
		}

		if spec.GetSource() == itemSpecDomain.SourceEcommerce {
			credentials, err := s.ecommerceCredSvc.GetCredentials(ctx, pointOfSaleID)
			if err == nil {
				cleanItemID := strings.TrimPrefix(spec.ItemId, "kivio-ecommerce∼")
				itemRaw, err := s.ecommerceSvc.GetItemByIDRaw(ctx, cleanItemID, credentials.ApiURL, credentials.ApiKey)

				if err == nil && itemRaw != nil {
					var extResp struct {
						Products []struct {
							StockQuantity int64 `json:"stock_quantity"`
						} `json:"products"`
					}
					if jsonErr := json.Unmarshal(itemRaw, &extResp); jsonErr == nil && len(extResp.Products) > 0 {
						spec.Availability = extResp.Products[0].StockQuantity
						s.itemSpecRepo.Save(ctx, &spec)
					}
				}
			}
		}

		result = append(result, ItemWithSpecification{
			Id:                 spec.Id,
			Amount:             spec.Amount,
			Currency:           spec.Currency,
			ExpireAt:           spec.ExpireAt.Format("2006-01-02T15:04:05Z07:00"),
			OfferId:            spec.OfferId,
			ItemId:             spec.ItemId,
			Availability:       spec.Availability,
			State:              string(spec.State),
			AllowMultipleItems: spec.AllowMultipleItems,
			MaxPricePercentage: spec.MaxPricePercentage,
			Item:               item,
		})
	}

	return result, nil
}
