package services

import (
	"context"
	"fmt"
	"sync"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
	itemInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/item"
	itemSpecInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/item_specification"
	orderInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/order"

	emailservices "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/email"
)

type OrderService interface {
	CreateOrder(ctx context.Context, input domain.OrderInput) (*domain.Order, error)
	GetOrders(ctx context.Context) ([]domain.Order, error)
	UpdateOrder(ctx context.Context, input domain.OrderInput) error
	GetOrderById(ctx context.Context, id string) (*domain.Order, error)
	GetOrderByItemSpecificationId(ctx context.Context, id string) ([]domain.Order, error)
	GetOrderByOfferId(ctx context.Context, id string) ([]domain.Order, error)
	DeleteOrderById(ctx context.Context, id string) error
	GetAllOrdersWithDetails(ctx context.Context) ([]domain.OrderDetail, error)
	GetPaginatedOrdersWithDetails(ctx context.Context, params domain.PaginationParams) (*domain.PaginatedOrdersResponse, error)
	UpdateOrderState(ctx context.Context, orderId string, state string) error
	NotifyAndCloseApprovedOrdersByPointOfSaleId(ctx context.Context, pointOfSaleId string, adminEmail string) error
}

type orderService struct {
	repo         orderInfrastructure.OrderRepository
	orderFactory domain.OrderFactory
	itemSpecRepo itemSpecInfrastructure.ItemSpecificationRepository
	itemRepo     itemInfrastructure.ItemRepository
	emailService emailservices.EmailServiceInterface
}

func NewOrderService(repo orderInfrastructure.OrderRepository, orderFactory domain.OrderFactory, itemSpecRepo itemSpecInfrastructure.ItemSpecificationRepository, itemRepo itemInfrastructure.ItemRepository, emailService emailservices.EmailServiceInterface) OrderService {
	return &orderService{repo: repo, orderFactory: orderFactory, itemSpecRepo: itemSpecRepo, itemRepo: itemRepo, emailService: emailService}
}

func (s *orderService) CreateOrder(ctx context.Context, input domain.OrderInput) (*domain.Order, error) {
	order, err := s.orderFactory.CreateOrder(
		input.CustomerId,
		input.ExternalId,
		input.ItemSpecificationId,
		input.OfferId,
		input.PointOfSaleId,
		input.ExtraData,
		input.OfferedAmount,
		input.AuctionService,
	)
	if err != nil {
		return &domain.Order{}, err
	}
	if input.WompiIdPayment == "" {
		order.State = "Created"
	} else {
		order.State = "Pending"
	}

	order.WompiIdPayment = input.WompiIdPayment
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

func (s *orderService) UpdateOrder(ctx context.Context, input domain.OrderInput) error {
	order, err := s.repo.GetIdOrder(ctx, input.OrderId)
	if err != nil {
		return err
	}
	err = order.Update(
		input.CustomerId,
		input.ExternalId,
		input.ItemSpecificationId,
		input.State,
		input.OfferedAmount,
		input.IsWinner,
	)
	if err != nil {
		return err
	}
	order.WompiIdPayment = input.WompiIdPayment
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

	if params.PointOfSaleId == "" {
		return nil, fmt.Errorf("pointOfSaleId is required")
	}

	var (
		wg         sync.WaitGroup
		totalCount int64
		countErr   error
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		totalCount, countErr = s.repo.CountOrders(ctx, params.PointOfSaleId)
	}()

	ordersResult, err := s.repo.GetOrdersPaginated(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("error al obtener órdenes paginadas: %w", err)
	}

	wg.Wait()
	if countErr != nil {
		fmt.Printf("Error al obtener el conteo total de órdenes: %v\n", countErr)
	}

	var orderDetails []domain.OrderDetail
	for _, order := range ordersResult.Orders {
		orderDetail := domain.OrderDetail{
			OrderId:     order.OrderId,
			State:       order.State,
			CreatedAt:   order.CreatedAt,
			CustomerId:  order.CustomerId,
			OrderAmount: order.OfferedAmount,
			ExtraData:   order.ExtraData,
		}
		orderDetails = append(orderDetails, orderDetail)
	}

	return &domain.PaginatedOrdersResponse{
		Orders:     orderDetails,
		NextToken:  ordersResult.NextToken,
		TotalCount: totalCount,
	}, nil
}

func (s *orderService) NotifyAndCloseApprovedOrdersByPointOfSaleId(ctx context.Context, pointOfSaleId string, adminEmail string) error {
	orders, err := s.repo.GetOrdersByPointOfSaleId(ctx, pointOfSaleId)
	if err != nil {
		return err
	}

	var approvedOrders []domain.Order
	for _, order := range orders {
		if order.State == "Approved" {
			approvedOrders = append(approvedOrders, order)
		}
	}

	if len(approvedOrders) == 0 {
		return nil
	}

	body := "Órdenes aprobadas:\n\n"
	for _, order := range approvedOrders {
		body += "OrderId: " + order.OrderId + ", CustomerId: " + order.CustomerId + ", Amount: " + fmt.Sprintf("%d", order.OfferedAmount) + "\n"
	}

	templateData := map[string]string{
		"ORDERS_LIST": body,
	}

	err = s.emailService.NotifyAdminApprovedOrders(ctx, adminEmail, templateData)
	if err != nil {
		return err
	}

	for _, order := range approvedOrders {
		order.State = "Closed"
		err := s.repo.SaveOrder(ctx, &order)
		if err != nil {
			return err
		}
	}

	return nil
}
