package services

import (
	"context"

	pointofsale "github.com/Kivio-Product/Kivio.Product.Auctions.Offers/internal/domain/pointOfSale"
	"github.com/Kivio-Product/Kivio.Product.Auctions.Offers/internal/infrastructure"
)

type IPosService interface {
	GeneratePointOfSale(ctx context.Context, description, name, userId string) (*pointofsale.PointOfSale, error)
	GetPosByUserId(ctx context.Context, id string) ([]pointofsale.PointOfSale, error)
	GetPosById(ctx context.Context, id string) (*pointofsale.PointOfSale, error)
	DeletePosById(ctx context.Context, id string) error
	UpdatePointOfSale(ctx context.Context, name, description, pointOfSaleId, userId string) error
	GetPos(ctx context.Context) ([]pointofsale.PointOfSale, error)
	GetusersById(ctx context.Context, id string) ([]pointofsale.UserByPos, error)
}

type PosService struct {
	repo       infrastructure.IPosRepository
	posFactory pointofsale.PosFactory
}

func NewPosService(repo infrastructure.IPosRepository, posFactory pointofsale.PosFactory) IPosService {
	return &PosService{repo: repo, posFactory: posFactory}
}

func (s *PosService) GeneratePointOfSale(ctx context.Context, description, name, userId string) (*pointofsale.PointOfSale, error) {
	pointOfSale, err := s.posFactory.CreatePointOfSale(description, name, userId)
	if err != nil {
		return &pointofsale.PointOfSale{}, err
	}
	pointOfSale = pointofsale.GenerateCreatedState(pointOfSale)
	if err := s.repo.SavePointOfSale(ctx, pointOfSale); err != nil {
		return nil, err
	}
	return pointOfSale, nil
}

func (s *PosService) GetPos(ctx context.Context) ([]pointofsale.PointOfSale, error) {
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

func (s *PosService) GetPosByUserId(ctx context.Context, id string) ([]pointofsale.PointOfSale, error) {
	items, err := s.repo.GetUserPos(id)
	if err != nil {
		return nil, err
	}
	return items, nil
}

func (s *PosService) GetPosById(ctx context.Context, id string) (*pointofsale.PointOfSale, error) {
	items, err := s.repo.GetPosById(ctx, id)
	if err != nil {
		return &pointofsale.PointOfSale{}, err
	}
	return items, nil
}

func (s *PosService) GetusersById(ctx context.Context, id string) ([]pointofsale.UserByPos, error) {
	items, err := s.repo.GetPosUser(id)
	if err != nil {
		return nil, err
	}
	return items, nil
}

func (s *PosService) DeletePosById(ctx context.Context, id string) error {
	err := s.repo.DeletePos(ctx, id)
	return err
}
