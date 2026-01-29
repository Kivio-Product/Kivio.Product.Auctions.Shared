package services

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	ecommerceService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/ecommerce"
	emailService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/email"
	applicationLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/logging"
	itemDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
	itemSpecDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item_specification"
	"github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/logging"
	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/offer"
	scheduler "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/scheduler"
	infrastructureLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/logging"
	itemRepository "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/item"
	itemSpecRepository "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/item_specification"
	infrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/offer"
	pointOfSaleRespository "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/point_of_sale"
	"github.com/aws/aws-sdk-go/service/dynamodb"
)

type IOfferService interface {
	GenerateOffer(ctx context.Context, name, description, posId, typer string, auctionTime, priceIncrease int64) (*domain.Offer, error)
	UpdateOffer(ctx context.Context, offerId, description, name string, auctionTime int64) error
	UpdateOfferState(ctx context.Context, offerId, state string) error
	GetOffers(ctx context.Context) ([]domain.Offer, error)
	GetOfferById(ctx context.Context, id string) (*domain.Offer, error)
	DeleteOfferById(ctx context.Context, id string) error
	GetOffersByPosId(ctx context.Context, id string, limit string, lastEvaluatedKey map[string]*dynamodb.AttributeValue) ([]domain.Offer, map[string]*dynamodb.AttributeValue, error)
	SendOfferEmail(ctx context.Context, auctionURL, unsubscribeUrl string, offerID string) error
	GetOffersWithSpecsAndItems(
		ctx context.Context,
		posId string,
		filters map[string]string,
		limit int,
		lastEvaluatedKey map[string]*dynamodb.AttributeValue,
	) ([]OfferWithItemsAndSpecs, map[string]*dynamodb.AttributeValue, int64, error)
	CountOffers(ctx context.Context) (int64, error)
}

type OfferService struct {
	repo                   infrastructure.IOfferRepository
	emailSender            emailService.EmailServiceInterface
	offerFactory           domain.OfferFactory
	itemRepository         itemRepository.ItemRepository
	itemSpecRepository     itemSpecRepository.ItemSpecificationRepository
	ecommerceService       ecommerceService.EcommerceService
	ecommerceCredSvc       ecommerceService.EcommerceCredentialsService
	scheduler              scheduler.SchedulerService
	pointOfSaleRespository pointOfSaleRespository.IPosRepository
	serviceLogger          *applicationLogging.ServiceLogger
	eventLogger            *logging.DomainEventLogger
}

type OfferWithDetails struct {
	Offer     domain.Offer
	Item      *itemDomain.Item
	ItemSpecs []itemSpecDomain.ItemSpecification
}

type ItemWithSpecs struct {
	Item      itemDomain.Item                    `json:"item"`
	ItemSpecs []itemSpecDomain.ItemSpecification `json:"item_specs"`
}

type OfferWithItemsAndSpecs struct {
	Offer domain.Offer    `json:"offer"`
	Items []ItemWithSpecs `json:"items"`
}

func NewofferService(repo infrastructure.IOfferRepository, offerFactory domain.OfferFactory, emailSender emailService.EmailServiceInterface, itemRepository itemRepository.ItemRepository, itemSpecRepository itemSpecRepository.ItemSpecificationRepository, ecommerceService ecommerceService.EcommerceService, ecommerceCredSvc ecommerceService.EcommerceCredentialsService, scheduler scheduler.SchedulerService, pointOfSaleRespository pointOfSaleRespository.IPosRepository) IOfferService {
	loggerRepo := infrastructureLogging.GetLoggerRepository()
	serviceLogger := applicationLogging.NewServiceLogger(loggerRepo, "OfferService")
	eventLogger := logging.NewDomainEventLogger(loggerRepo.GetLogger())

	return &OfferService{
		repo:                   repo,
		offerFactory:           offerFactory,
		emailSender:            emailSender,
		itemRepository:         itemRepository,
		itemSpecRepository:     itemSpecRepository,
		ecommerceService:       ecommerceService,
		ecommerceCredSvc:       ecommerceCredSvc,
		scheduler:              scheduler,
		pointOfSaleRespository: pointOfSaleRespository,
		serviceLogger:          serviceLogger,
		eventLogger:            eventLogger,
	}
}

func (s *OfferService) SendOfferEmail(ctx context.Context, auctionURL, unsubscribeUrl string, offerID string) error {
	start := time.Now()
	s.serviceLogger.LogServiceStart(ctx, "SendOfferEmail", map[string]interface{}{
		"offer_id":    offerID,
		"auction_url": auctionURL,
	})

	offer, err := s.GetOfferById(ctx, offerID)
	if err != nil {
		s.serviceLogger.LogServiceError(ctx, "SendOfferEmail", err, map[string]interface{}{
			"offer_id": offerID,
			"error":    "failed_to_get_offer",
		})
		return err
	}
	pos, err := s.pointOfSaleRespository.GetPosById(ctx, offer.PosId)
	if err != nil {
		s.serviceLogger.LogServiceError(ctx, "SendOfferEmail", err, map[string]interface{}{
			"offer_id": offerID,
			"pos_id":   offer.PosId,
			"error":    "failed_to_get_pos",
		})
		return err
	}

	err = s.emailSender.NotifyOffer(ctx, auctionURL, unsubscribeUrl, offer.Name, offer.PosId, pos.Name)
	if err != nil {
		s.serviceLogger.LogServiceError(ctx, "SendOfferEmail", err, map[string]interface{}{
			"offer_id":   offerID,
			"pos_id":     offer.PosId,
			"offer_name": offer.Name,
			"error":      "failed_to_send_email",
		})
		return err
	}

	s.serviceLogger.LogServiceEnd(ctx, "SendOfferEmail", time.Since(start), map[string]interface{}{
		"offer_id":   offerID,
		"pos_id":     offer.PosId,
		"offer_name": offer.Name,
		"success":    true,
	})

	return nil
}

func (s *OfferService) GenerateOffer(ctx context.Context, name, description, posId, typer string, auctionTime, priceIncrease int64) (*domain.Offer, error) {
	start := time.Now()
	s.serviceLogger.LogServiceStart(ctx, "GenerateOffer", map[string]interface{}{
		"offer_name":   name,
		"pos_id":       posId,
		"offer_type":   typer,
		"auction_time": auctionTime,
		"price_increase": priceIncrease,
	})

	offers, err := s.offerFactory.CreateOffer(name, description, posId, typer, auctionTime, priceIncrease)
	if err != nil {
		s.serviceLogger.LogServiceError(ctx, "GenerateOffer", err, map[string]interface{}{
			"offer_name": name,
			"pos_id":     posId,
			"error":      "failed_to_create_offer",
		})
		return &domain.Offer{}, err
	}

	err = offers.UpdateState("Created")
	if err != nil {
		s.serviceLogger.LogServiceError(ctx, "GenerateOffer", err, map[string]interface{}{
			"offer_id": offers.OfferId,
			"error":    "failed_to_update_state",
		})
		return &domain.Offer{}, err
	}

	if err := s.repo.SaveOffer(ctx, offers); err != nil {
		s.serviceLogger.LogServiceError(ctx, "GenerateOffer", err, map[string]interface{}{
			"offer_id": offers.OfferId,
			"error":    "failed_to_save_offer",
		})
		return &domain.Offer{}, err
	}

	s.eventLogger.LogOfferStateChange(ctx, offers.OfferId, "", "Created")
	s.serviceLogger.LogServiceEnd(ctx, "GenerateOffer", time.Since(start), map[string]interface{}{
		"offer_id":      offers.OfferId,
		"offer_name":    name,
		"pos_id":        posId,
		"initial_state": "Created",
		"success":       true,
	})

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
	start := time.Now()
	s.serviceLogger.LogServiceStart(ctx, "UpdateOfferState", map[string]interface{}{
		"offer_id":  offerId,
		"new_state": state,
	})

	offer, err := s.repo.GetOfferById(ctx, offerId)
	if err != nil {
		s.serviceLogger.LogServiceError(ctx, "UpdateOfferState", err, map[string]interface{}{
			"offer_id": offerId,
			"error":    "failed_to_get_offer",
		})
		return err
	}

	oldState := offer.State
	err = offer.UpdateState(state)
	if err != nil {
		s.serviceLogger.LogServiceError(ctx, "UpdateOfferState", err, map[string]interface{}{
			"offer_id":  offerId,
			"old_state": oldState,
			"new_state": state,
			"error":     "failed_to_update_state",
		})
		return err
	}

	if state == domain.StateActive {
		offer.SetOfferTime(time.Now())
		if offer.OfferTime != nil && offer.Type == "Regular auction" {
			timeToSum := time.Duration(offer.AuctionTime)*time.Hour + 2*time.Minute
			ruleName := fmt.Sprintf("%s-activate-offer-%s", os.Getenv("AUCTIONS_ENV_NAME"), offer.OfferId)
			payload := fmt.Sprintf(`{"offerId":"%s"}`, offer.OfferId)
			lambdaArn := os.Getenv("ORDER_STATE_LAMBDA_ARN")
			err := s.scheduler.ScheduleLambda(*offer.OfferTime, timeToSum, lambdaArn, ruleName, payload)
			if err != nil {
				s.serviceLogger.LogServiceError(ctx, "UpdateOfferState", err, map[string]interface{}{
					"offer_id":     offerId,
					"rule_name":    ruleName,
					"lambda_arn":   lambdaArn,
					"auction_time": offer.AuctionTime,
					"error":        "failed_to_schedule_lambda",
				})
				fmt.Printf("Error programando schedule para oferta %s: %v\n", offer.OfferId, err)
			} else {
				s.serviceLogger.LogWorkflow(ctx, "OfferActivation", "ScheduledLambda", map[string]interface{}{
					"offer_id":     offerId,
					"rule_name":    ruleName,
					"auction_time": offer.AuctionTime,
					"time_to_sum":  timeToSum.String(),
				})
			}
		}
	}

	err = s.repo.SaveOffer(ctx, offer)
	if err != nil {
		s.serviceLogger.LogServiceError(ctx, "UpdateOfferState", err, map[string]interface{}{
			"offer_id":  offerId,
			"old_state": oldState,
			"new_state": state,
			"error":     "failed_to_save_offer",
		})
		return err
	}

	s.eventLogger.LogOfferStateChange(ctx, offerId, oldState, state)
	s.serviceLogger.LogServiceEnd(ctx, "UpdateOfferState", time.Since(start), map[string]interface{}{
		"offer_id":  offerId,
		"old_state": oldState,
		"new_state": state,
		"success":   true,
	})

	return nil
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
	offer, err := s.repo.GetOfferById(ctx, id)
	if err != nil {
		return err
	}
	if offer.State == domain.StateActive {
		return fmt.Errorf("No se puede eliminar una oferta con estado 'Offered'")
	}
	return s.repo.DeleteOffer(ctx, id)
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
	filters map[string]string,
	limit int,
	lastEvaluatedKey map[string]*dynamodb.AttributeValue,
) ([]OfferWithItemsAndSpecs, map[string]*dynamodb.AttributeValue, int64, error) {
	offers, lastKey, total, err := s.repo.GetPosOffersFiltered(posId, filters, limit, lastEvaluatedKey)
	if err != nil {
		return nil, nil, 0, err
	}
	if len(offers) == 0 {
		return nil, lastKey, total, nil
	}

	offerIds := make([]string, len(offers))
	for i, offer := range offers {
		offerIds[i] = offer.OfferId
	}

	itemSpecs, err := s.itemSpecRepository.GetItemSpecsByOfferIds(ctx, offerIds, posId)
	if err != nil {
		return nil, nil, 0, err
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
	creds, err := s.ecommerceCredSvc.GetCredentials(ctx, posId)
	for _, spec := range externalSpecs {
		wg.Add(1)
		go func(spec itemSpecDomain.ItemSpecification) {
			defer wg.Done()

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

	specsByOfferAndItem := make(map[string]map[string][]itemSpecDomain.ItemSpecification)
	for _, spec := range itemSpecs {
		if _, ok := specsByOfferAndItem[spec.OfferId]; !ok {
			specsByOfferAndItem[spec.OfferId] = make(map[string][]itemSpecDomain.ItemSpecification)
		}
		specsByOfferAndItem[spec.OfferId][spec.ItemId] = append(specsByOfferAndItem[spec.OfferId][spec.ItemId], spec)
	}

	var result []OfferWithItemsAndSpecs
	for _, offer := range offers {
		itemSpecsMap := specsByOfferAndItem[offer.OfferId]
		var itemsWithSpecs []ItemWithSpecs
		for itemId, specs := range itemSpecsMap {
			var item itemDomain.Item
			if len(specs) > 0 && specs[0].IsExternal {
				itm, ok := externalItemsMap[itemId]
				if !ok {
					continue
				}
				item = itm
			} else {
				itm, ok := itemsMap[itemId]
				if !ok {
					continue
				}
				item = itm
			}
			itemsWithSpecs = append(itemsWithSpecs, ItemWithSpecs{
				Item:      item,
				ItemSpecs: specs,
			})
		}
		result = append(result, OfferWithItemsAndSpecs{
			Offer: offer,
			Items: itemsWithSpecs,
		})
	}
	return result, lastKey, total, nil
}

func (s *OfferService) CountOffers(ctx context.Context) (int64, error) {
	return s.repo.CountOffers(ctx)
}
