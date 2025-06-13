package services

import (
	"context"
	"strconv"
	"sync"

	ecommerceService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/ecommerce"
	emailService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/email"
	itemDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
	itemSpecDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item_specification"
	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/offer"
	itemRepository "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/item"
	itemSpecRepository "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/item_specification"
	infrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/offer"
	"github.com/aws/aws-sdk-go/service/dynamodb"
)

type IOfferService interface {
	GenerateOffer(ctx context.Context, name, description, posId, typer string, auctionTime int64) (*domain.Offer, error)
	UpdateOffer(ctx context.Context, offerId, description, name string, auctionTime int64) error
	UpdateOfferState(ctx context.Context, offerId, state string) error
	GetOffers(ctx context.Context) ([]domain.Offer, error)
	GetOfferById(ctx context.Context, id string) (*domain.Offer, error)
	DeleteOfferById(ctx context.Context, id string) error
	GetOffersByPosId(ctx context.Context, id string, limit string, lastEvaluatedKey map[string]*dynamodb.AttributeValue) ([]domain.Offer, map[string]*dynamodb.AttributeValue, error)
	SendOfferEmail(ctx context.Context, auctionURL string, offerID string) error
	GetOffersWithSpecsAndItems(
		ctx context.Context,
		posId string,
		limit int,
		lastEvaluatedKey map[string]*dynamodb.AttributeValue,
	) ([]ItemWithSpec, map[string]*dynamodb.AttributeValue, error)
}

type OfferService struct {
	repo               infrastructure.IOfferRepository
	emailSender        emailService.EmailServiceInterface
	offerFactory       domain.OfferFactory
	itemRepository     itemRepository.ItemRepository
	itemSpecRepository itemSpecRepository.ItemSpecificationRepository
	ecommerceService   ecommerceService.EcommerceService
	ecommerceCredSvc   ecommerceService.EcommerceCredentialsService
}

type OfferWithDetails struct {
	Offer     domain.Offer
	Item      *itemDomain.Item
	ItemSpecs []itemSpecDomain.ItemSpecification
}

type ItemWithSpec struct {
	Item     itemDomain.Item                  `json:"item"`
	ItemSpec itemSpecDomain.ItemSpecification `json:"item_specs"`
}

func NewofferService(repo infrastructure.IOfferRepository, offerFactory domain.OfferFactory, emailSender emailService.EmailServiceInterface, itemRepository itemRepository.ItemRepository, itemSpecRepository itemSpecRepository.ItemSpecificationRepository, ecommerceService ecommerceService.EcommerceService, ecommerceCredSvc ecommerceService.EcommerceCredentialsService) IOfferService {
	return &OfferService{
		repo:               repo,
		offerFactory:       offerFactory,
		emailSender:        emailSender,
		itemRepository:     itemRepository,
		itemSpecRepository: itemSpecRepository,
		ecommerceService:   ecommerceService,
		ecommerceCredSvc:   ecommerceCredSvc,
	}
}

func (s *OfferService) SendOfferEmail(ctx context.Context, auctionURL string, offerID string) error {
	offer, err := s.GetOfferById(ctx, offerID)
	if err != nil {
		return err
	}
	return s.emailSender.NotifyOffer(ctx, auctionURL, offer.Name, offer.PosId)
}

func (s *OfferService) GenerateOffer(ctx context.Context, name, description, posId, typer string, auctionTime int64) (*domain.Offer, error) {
	offers, err := s.offerFactory.CreateOffer(name, description, posId, typer, auctionTime)
	if err != nil {
		return &domain.Offer{}, err
	}
	err = offers.UpdateState("Created")
	if err := s.repo.SaveOffer(ctx, offers); err != nil {
		return &domain.Offer{}, err
	}
	return offers, nil
}

func (s *OfferService) UpdateOffer(ctx context.Context, offerId, description, name string, auctionTime int64) error {
	offer, err := s.repo.GetOfferById(ctx, offerId)
	err = offer.Update(name, description, auctionTime)
	if err != nil {
		return err
	}
	return s.repo.SaveOffer(ctx, offer)
}

func (s *OfferService) UpdateOfferState(ctx context.Context, offerId, state string) error {
	offer, err := s.repo.GetOfferById(ctx, offerId)
	err = offer.UpdateState(state)
	if err != nil {
		return err
	}
	return s.repo.SaveOffer(ctx, offer)
}

func (s *OfferService) GetOffers(ctx context.Context) ([]domain.Offer, error) {
	offers, err := s.repo.GetAllOffers()
	if err != nil {
		return nil, err
	}
	return offers, nil
}

func (s *OfferService) GetOfferById(ctx context.Context, id string) (*domain.Offer, error) {
	items, err := s.repo.GetOfferById(ctx, id)
	if err != nil {
		return &domain.Offer{}, err
	}
	return items, nil
}

func (s *OfferService) DeleteOfferById(ctx context.Context, id string) error {
	err := s.repo.DeleteOffer(ctx, id)
	return err
}

func (s *OfferService) GetOffersByPosId(ctx context.Context, id string, limit string, lastEvaluatedKey map[string]*dynamodb.AttributeValue) ([]domain.Offer, map[string]*dynamodb.AttributeValue, error) {
	limitInt := 0
	if limit != "" {
		var err error
		limitInt, err = strconv.Atoi(limit)
		if err != nil {
			return nil, nil, err
		}
	}

	offers, lastKey, err := s.repo.GetPosOffers(id, limitInt, lastEvaluatedKey)
	if err != nil {
		return nil, nil, err
	}
	return offers, lastKey, nil
}

func (s *OfferService) GetOffersWithSpecsAndItems(
	ctx context.Context,
	posId string,
	limit int,
	lastEvaluatedKey map[string]*dynamodb.AttributeValue,
) ([]ItemWithSpec, map[string]*dynamodb.AttributeValue, error) {
	offers, lastKey, err := s.repo.GetPosOffers(posId, limit, lastEvaluatedKey)
	if err != nil {
		return nil, nil, err
	}
	if len(offers) == 0 {
		return nil, lastKey, nil
	}

	offerIds := make([]string, len(offers))
	for i, offer := range offers {
		offerIds[i] = offer.OfferId
	}

	itemSpecs, err := s.itemSpecRepository.GetItemSpecsByOfferIds(ctx, offerIds, posId)
	if err != nil {
		return nil, nil, err
	}

	itemIdSet := make(map[string]struct{})
	externalSpecs := []itemSpecDomain.ItemSpecification{}
	for _, spec := range itemSpecs {
		if spec.IsExternal {
			externalSpecs = append(externalSpecs, spec)
		} else {
			itemIdSet[spec.ItemId] = struct{}{}
		}
	}
	itemIds := make([]string, 0, len(itemIdSet))
	for id := range itemIdSet {
		itemIds = append(itemIds, id)
	}

	itemsMap := make(map[string]itemDomain.Item)
	if len(itemIds) > 0 {
		items, _ := s.itemRepository.BatchGetItemsByIds(ctx, itemIds)
		for _, item := range items {
			itemsMap[item.ItemId] = item
		}
	}

	externalItemsMap := make(map[string]itemDomain.Item)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, spec := range externalSpecs {
		wg.Add(1)
		go func(spec itemSpecDomain.ItemSpecification) {
			defer wg.Done()
			creds, err := s.ecommerceCredSvc.GetCredentials(ctx, spec.PointOfSaleId)
			if err != nil {
				return
			}
			item, err := s.ecommerceService.GetItemByID(ctx, spec.ItemId, creds.ApiURL, creds.ApiKey)
			if err != nil || item == nil {
				return
			}
			mu.Lock()
			externalItemsMap[spec.ItemId] = *item
			mu.Unlock()
		}(spec)
	}
	wg.Wait()

	var result []ItemWithSpec
	for _, spec := range itemSpecs {
		var item itemDomain.Item
		if spec.IsExternal {
			itm, ok := externalItemsMap[spec.ItemId]
			if !ok {
				continue
			}
			item = itm
		} else {
			itm, ok := itemsMap[spec.ItemId]
			if !ok {
				continue
			}
			item = itm
		}
		result = append(result, ItemWithSpec{
			Item:     item,
			ItemSpec: spec,
		})
	}
	return result, lastKey, nil
}
