package services

import (
	"context"
	"fmt"
	"time"

	"github.com/Kivio-Product/Kivio.Product.Auctions.Services/internal/domain"
	"github.com/Kivio-Product/Kivio.Product.Auctions.Services/internal/infrastructure"
)

type ItemSpecificationService interface {
	Create(ctx context.Context, currency, offerId, itemId string, amount, availability int64, expireAt time.Time, isExternal bool) (*domain.ItemSpecification, error)
	Get() ([]domain.ItemSpecification, error)
	GetById(ctx context.Context, id string) (*domain.ItemSpecification, error)
	Update(ctx context.Context, id, currency, offerId, itemId string, amount, availability int64, expireAt time.Time) error
	Delete(ctx context.Context, id string) error
	GetItemSpecByOfferId(ctx context.Context, id string) ([]domain.ItemSpecification, error)
	GetItemSpecByItemId(ctx context.Context, id string) ([]domain.ItemSpecification, error)
}

type itemSpecificationService struct {
	repo                     infrastructure.ItemSpecificationRepository
	itemSpecificationFactory domain.ItemSpecificationFactory
}

func NewItemSpecificationService(repo infrastructure.ItemSpecificationRepository, itemSpecificationFactory domain.ItemSpecificationFactory) ItemSpecificationService {
	return &itemSpecificationService{repo: repo, itemSpecificationFactory: itemSpecificationFactory}
}

func (s *itemSpecificationService) Create(ctx context.Context, currency, offerId, itemId string, amount, availability int64, expireAt time.Time, isExternal bool) (*domain.ItemSpecification, error) {
	itemSpecification, err := s.itemSpecificationFactory.CreateItemSpecification(currency, offerId, itemId, amount, availability, expireAt, isExternal)

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

func (s *itemSpecificationService) Update(ctx context.Context, id, currency, offerId, itemId string, amount, availability int64, expireAt time.Time) error {
	item, err := s.repo.GetById(ctx, id)
	err = item.Update(currency, offerId, itemId, amount, availability, expireAt)
	if err != nil {
		return err
	}
	return s.repo.Save(ctx, item)
}

func (s *itemSpecificationService) Delete(ctx context.Context, id string) error {
	err := s.repo.Delete(ctx, id)
	return err
}

func (s *itemSpecificationService) GetItemSpecByOfferId(ctx context.Context, id string) ([]domain.ItemSpecification, error) {
	itemsSpec, err := s.repo.GetItemSpecByOffer(id)

	fmt.Println("itemSpecification", itemsSpec)
	if err != nil {
		return nil, err
	}
	return itemsSpec, nil
}

func (s *itemSpecificationService) GetItemSpecByItemId(ctx context.Context, id string) ([]domain.ItemSpecification, error) {
	order, err := s.repo.GetItemSpecByItem(id)
	if err != nil {
		return nil, err
	}
	return order, nil
}
