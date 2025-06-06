package services

import (
	"context"
	"fmt"
	"log"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
	itemInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/item"
	itemSpecInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/item_specification"
	orderInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/order"
)

type OrderService interface {
	CreateOrder(ctx context.Context, customerId, externalId, itemId, offerId, pointOfSaleId, extraData string, offeredAmount int64) (*domain.Order, error)
	GetOrders(ctx context.Context) ([]domain.Order, error)
	UpdateOrder(ctx context.Context, orderId string, offeredAmount int64, customerId, externalId, itemId, state string) error
	GetOrderById(ctx context.Context, id string) (*domain.Order, error)
	GetOrderByItemSpecificationId(ctx context.Context, id string) ([]domain.Order, error)
	GetOrderByOfferId(ctx context.Context, id string) ([]domain.Order, error)
	DeleteOrderById(ctx context.Context, id string) error
	GetAllOrdersWithDetails(ctx context.Context) ([]domain.OrderDetail, error)
	GetPaginatedOrdersWithDetails(ctx context.Context, params domain.PaginationParams) (*domain.PaginatedOrdersResponse, error)
	UpdateOrderState(ctx context.Context, orderId string, state string) error
}

type orderService struct {
	repo         orderInfrastructure.OrderRepository
	orderFactory domain.OrderFactory
	itemSpecRepo itemSpecInfrastructure.ItemSpecificationRepository
	itemRepo     itemInfrastructure.ItemRepository
}

func NewOrderService(repo orderInfrastructure.OrderRepository, orderFactory domain.OrderFactory, itemSpecRepo itemSpecInfrastructure.ItemSpecificationRepository, itemRepo itemInfrastructure.ItemRepository) OrderService {
	return &orderService{repo: repo, orderFactory: orderFactory, itemSpecRepo: itemSpecRepo, itemRepo: itemRepo}
}

func (s *orderService) CreateOrder(ctx context.Context, customerId, externalId, itemId, offerId, pointOfSaleId, extraData string, offeredAmount int64) (*domain.Order, error) {
	order, err := s.orderFactory.CreateOrder(customerId, externalId, itemId, offerId, pointOfSaleId, extraData, offeredAmount)
	if err != nil {
		return &domain.Order{}, err
	}
	order.State = "Created"
	err = s.repo.SaveOrder(ctx, order)

	if err != nil {
		return &domain.Order{}, err
	}

	return order, nil
}

func (s *orderService) GetOrders(ctx context.Context) ([]domain.Order, error) {
	orders, err := s.repo.GetAllOrders(ctx)
	if err != nil {
		return nil, err
	}
	return orders, nil
}

func (s *orderService) UpdateOrder(ctx context.Context, orderId string, offeredAmount int64, customerId, externalId, itemId, state string) error {
	order, err := s.repo.GetIdOrder(ctx, orderId)
	err = order.Update(customerId, externalId, itemId, state, offeredAmount)
	if err != nil {
		return err
	}
	return s.repo.SaveOrder(ctx, order)
}

func (s *orderService) UpdateOrderState(ctx context.Context, orderId string, state string) error {
	order, err := s.repo.GetIdOrder(ctx, orderId)
	if err != nil {
		return err
	}
	order.State = state
	return s.repo.SaveOrder(ctx, order)
}

func (s *orderService) GetAllOrdersWithDetails(ctx context.Context) ([]domain.OrderDetail, error) {
	orders, err := s.repo.GetAllOrders(ctx)
	if err != nil {
		return nil, err
	}

	var orderDetails []domain.OrderDetail
	for _, order := range orders {
		itemSpecification, err := s.itemSpecRepo.GetById(ctx, order.ItemSpecificationId)
		if err != nil {
			continue
		}

		item, err := s.itemRepo.GetItemById(ctx, itemSpecification.ItemId)
		if err != nil {
			continue
		}

		orderDetail := domain.OrderDetail{
			OrderId:         order.OrderId,
			ItemName:        item.Name,
			State:           order.State,
			CreatedAt:       order.CreatedAt,
			CustomerId:      order.CustomerId,
			ItemAmount:      itemSpecification.Amount,
			OrderAmount:     order.OfferedAmount,
			ItemDescription: item.Description,
		}
		orderDetails = append(orderDetails, orderDetail)
	}

	return orderDetails, nil
}

func (s *orderService) GetOrderById(ctx context.Context, id string) (*domain.Order, error) {
	items, err := s.repo.GetIdOrder(ctx, id)
	if err != nil {
		return &domain.Order{}, err
	}
	return items, nil
}

func (s *orderService) GetOrderByItemSpecificationId(ctx context.Context, id string) ([]domain.Order, error) {
	order, err := s.repo.GetItemSpecificationOrder(id)
	if err != nil {
		return nil, err
	}
	return order, nil
}

func (s *orderService) GetOrderByOfferId(ctx context.Context, id string) ([]domain.Order, error) {
	order, err := s.repo.GetOfferOrder(id)
	if err != nil {
		return nil, err
	}
	return order, nil
}

func (s *orderService) DeleteOrderById(ctx context.Context, id string) error {
	err := s.repo.DeleteOrder(ctx, id)
	return err
}

func (s *orderService) GetPaginatedOrdersWithDetails(ctx context.Context, params domain.PaginationParams) (*domain.PaginatedOrdersResponse, error) {
	if params.PageSize < 1 {
		params.PageSize = 10
	}
	if params.PageSize > 100 {
		params.PageSize = 100
	}

	ordersResult, err := s.repo.GetOrdersPaginated(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("error al obtener órdenes paginadas: %w", err)
	}

	var orderDetails []domain.OrderDetail
	for _, order := range ordersResult.Orders {
		itemSpecification, err := s.itemSpecRepo.GetById(ctx, order.ItemSpecificationId)
		if err != nil {
			log.Printf("No se pudo obtener la especificación del item: error=%s, item_spec_id=%s, order_id=%s",
				err.Error(),
				order.ItemSpecificationId,
				order.OrderId)
			continue
		}

		item, err := s.itemRepo.GetItemById(ctx, itemSpecification.ItemId)
		if err != nil {
			log.Printf("No se pudo obtener el item: error=%s, item_id=%s, order_id=%s",
				err.Error(),
				itemSpecification.ItemId,
				order.OrderId)
			continue
		}

		orderDetail := domain.OrderDetail{
			OrderId:         order.OrderId,
			ItemName:        item.Name,
			State:           order.State,
			CreatedAt:       order.CreatedAt,
			CustomerId:      order.CustomerId,
			ItemAmount:      itemSpecification.Amount,
			OrderAmount:     order.OfferedAmount,
			ItemDescription: item.Description,
		}
		orderDetails = append(orderDetails, orderDetail)
	}

	return &domain.PaginatedOrdersResponse{
		Orders:     orderDetails,
		NextToken:  ordersResult.NextToken,
		TotalCount: ordersResult.TotalCount,
	}, nil
}
