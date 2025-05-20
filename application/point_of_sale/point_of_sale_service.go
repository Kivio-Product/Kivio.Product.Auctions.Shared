package services

import (
	"context"
	"fmt"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/point_of_sale"
	infrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/point_of_sale"
)

type IPosService interface {
	GeneratePointOfSale(ctx context.Context, description, name, userId string) (*domain.PointOfSale, error)
	GetPosByUserId(ctx context.Context, id string) ([]domain.PointOfSale, error)
	GetPosById(ctx context.Context, id string) (*domain.PointOfSale, error)
	DeletePosById(ctx context.Context, id string) error
	UpdatePointOfSale(ctx context.Context, name, description, pointOfSaleId, userId string) error
	GetPos(ctx context.Context) ([]domain.PointOfSale, error)
}

type PosService struct {
	repo       infrastructure.IPosRepository
	posFactory domain.PosFactory
}

func NewPosService(repo infrastructure.IPosRepository, posFactory domain.PosFactory) IPosService {
	return &PosService{repo: repo, posFactory: posFactory}
}

func (s *PosService) GeneratePointOfSale(ctx context.Context, description, name, userId string) (*domain.PointOfSale, error) {
	existingPos, err := s.repo.GetPosByUser(userId)
	if err != nil {
		return nil, fmt.Errorf("error checking existing PointOfSale for user: %w", err)
	}

	if len(existingPos) > 0 {
		return nil, fmt.Errorf("user '%s' already has a PointOfSale", userId)
	}

	pointOfSale, err := s.posFactory.CreatePointOfSale(description, name, userId)
	if err != nil {
		return nil, err
	}

	pointOfSale = domain.GenerateCreatedState(pointOfSale)

	if err := s.repo.SavePointOfSale(ctx, pointOfSale); err != nil {
		return nil, err
	}

	return pointOfSale, nil
}

func (s *PosService) GetPos(ctx context.Context) ([]domain.PointOfSale, error) {
	pos, err := s.repo.GetAllPos()
	if err != nil {
		return nil, err
	}
	return pos, nil
}

func (s *PosService) UpdatePointOfSale(ctx context.Context, name, description, pointOfSaleId, userId string) error {
	pointOfSale, err := s.repo.GetPosById(ctx, pointOfSaleId)
	pointOfSale.Update(name, description, pointOfSaleId, userId)
	if err != nil {
		return err
	}
	return s.repo.SavePointOfSale(ctx, pointOfSale)
}

func (s *PosService) GetPosByUserId(ctx context.Context, id string) ([]domain.PointOfSale, error) {
	items, err := s.repo.GetPosByUser(id)
	if err != nil {
		return nil, err
	}
	return items, nil
}

func (s *PosService) GetPosById(ctx context.Context, id string) (*domain.PointOfSale, error) {
	items, err := s.repo.GetPosById(ctx, id)
	if err != nil {
		return &domain.PointOfSale{}, err
	}
	return items, nil
}

func (s *PosService) DeletePosById(ctx context.Context, id string) error {
	err := s.repo.DeletePos(ctx, id)
	return err
}
