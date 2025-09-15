package services

import (
	"context"
	"fmt"
	"log"
	"time"

	applicationLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/logging"
	"github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/logging"
	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
	itemInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/item"
	itemSpecInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/item_specification"
	orderInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/order"
	infrastructureLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/logging"

	"bytes"

	billing "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/billing"
	emailservices "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/email"
	offerService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/offer"
	payment "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/payment"
	"github.com/jung-kurt/gofpdf"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

type OrderService interface {
	CreateOrder(ctx context.Context, input domain.OrderInput) (*domain.Order, error)
	CreateMultipleItemsOrder(ctx context.Context, input domain.OrderInput) (*domain.Order, error)
	GetOrders(ctx context.Context) ([]domain.Order, error)
	UpdateOrder(ctx context.Context, input domain.OrderInput) error
	GetOrderById(ctx context.Context, id string) (*domain.Order, error)
	GetOrderByItemSpecificationId(ctx context.Context, id string) ([]domain.Order, error)
	GetOrderByOfferId(ctx context.Context, id string) ([]domain.Order, error)
	DeleteOrderById(ctx context.Context, id string) error
	GetAllOrdersWithDetails(ctx context.Context) ([]domain.OrderDetail, error)
	GetOrdersBillingByID(ctx context.Context, id string) ([]domain.Order, error)
	GetPaginatedOrdersWithDetails(ctx context.Context, params domain.PaginationParams, filters map[string]string) (*domain.PaginatedOrdersResponse, error)
	UpdateOrderState(ctx context.Context, orderId string, state string) error
	NotifyAndCloseApprovedOrdersByPointOfSaleId(ctx context.Context, pointOfSaleId string, adminEmail string) error
}

type orderService struct {
	repo           orderInfrastructure.OrderRepository
	orderFactory   domain.OrderFactory
	itemSpecRepo   itemSpecInfrastructure.ItemSpecificationRepository
	itemRepo       itemInfrastructure.ItemRepository
	emailService   emailservices.EmailServiceInterface
	offerService   offerService.IOfferService
	wompiService   payment.WompiService
	billingService billing.BillingService
	serviceLogger  *applicationLogging.ServiceLogger
	eventLogger    *logging.DomainEventLogger
}

func NewOrderService(repo orderInfrastructure.OrderRepository, orderFactory domain.OrderFactory, itemSpecRepo itemSpecInfrastructure.ItemSpecificationRepository, itemRepo itemInfrastructure.ItemRepository, emailService emailservices.EmailServiceInterface, offerService offerService.IOfferService, wompiService payment.WompiService, billingService billing.BillingService) OrderService {
	loggerRepo := infrastructureLogging.GetLoggerRepository()
	serviceLogger := applicationLogging.NewServiceLogger(loggerRepo, "OrderService")
	eventLogger := logging.NewDomainEventLogger(loggerRepo.GetLogger())

	return &orderService{
		repo:          repo,
		orderFactory:  orderFactory,
		itemSpecRepo:  itemSpecRepo,
		itemRepo:      itemRepo,
		emailService:  emailService,
		offerService:  offerService,
		wompiService:  wompiService,
		billingService: billingService,
		serviceLogger: serviceLogger,
		eventLogger:   eventLogger,
	}
}

func (s *orderService) CreateOrder(ctx context.Context, input domain.OrderInput) (*domain.Order, error) {
	start := time.Now()
	s.serviceLogger.LogServiceStart(ctx, "CreateOrder", map[string]interface{}{
		"customer_id":           input.CustomerId,
		"offer_id":              input.OfferId,
		"item_specification_id": input.ItemSpecificationId,
		"pos_id":                input.PointOfSaleId,
		"offered_amount":        input.OfferedAmount,
		"has_wompi_payment":     input.WompiIdPayment != "",
	})

	order, err := s.orderFactory.CreateOrder(
		input.CustomerId,
		input.ExternalId,
		input.ItemSpecificationId,
		input.OfferId,
		input.PointOfSaleId,
		input.BillingId,
		input.ExtraData,
		input.OfferedAmount,
		1, // Default quantity to 1 for single item orders
	)
	if err != nil {
		s.serviceLogger.LogServiceError(ctx, "CreateOrder", err, map[string]interface{}{
			"customer_id": input.CustomerId,
			"offer_id":    input.OfferId,
			"error":       "failed_to_create_order",
		})
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
		s.serviceLogger.LogServiceError(ctx, "CreateOrder", err, map[string]interface{}{
			"order_id":    order.OrderId,
			"customer_id": input.CustomerId,
			"error":       "failed_to_save_order",
		})
		return &domain.Order{}, err
	}

	s.eventLogger.LogOrderCreated(ctx, order.OrderId, order.CustomerId, float64(order.OfferedAmount))
	s.serviceLogger.LogServiceEnd(ctx, "CreateOrder", time.Since(start), map[string]interface{}{
		"order_id":      order.OrderId,
		"customer_id":   input.CustomerId,
		"offer_id":      input.OfferId,
		"initial_state": order.State,
		"amount":        order.OfferedAmount,
		"success":       true,
	})

	return order, nil
}

func (s *orderService) CreateMultipleItemsOrder(ctx context.Context, input domain.OrderInput) (*domain.Order, error) {

	if len(input.Items) > 1 {
		for _, orderItem := range input.Items {
			itemSpec, err := s.itemSpecRepo.GetById(ctx, orderItem.ItemSpecificationId)
			if err != nil {
				return &domain.Order{}, fmt.Errorf("error getting item specification %s: %w", orderItem.ItemSpecificationId, err)
			}

			if !itemSpec.AllowMultipleItems {
				return &domain.Order{}, fmt.Errorf("item specification %s does not allow multiple items in orders", orderItem.ItemSpecificationId)
			}
		}
	}

	for _, orderItem := range input.Items {
		itemSpec, err := s.itemSpecRepo.GetById(ctx, orderItem.ItemSpecificationId)
		if err != nil {
			return &domain.Order{}, fmt.Errorf("error getting item specification %s: %w", orderItem.ItemSpecificationId, err)
		}

		if !itemSpec.AllowMultipleItems {
			return &domain.Order{}, fmt.Errorf("item specification %s does not allow multiple items in orders", orderItem.ItemSpecificationId)
		}

		if itemSpec.Availability < int64(orderItem.Quantity) {
			return &domain.Order{}, fmt.Errorf("insufficient availability for item %s: required %d, available %d",
				orderItem.ItemSpecificationId, orderItem.Quantity, itemSpec.Availability)
		}
	}

	order, err := s.orderFactory.CreateOrder(
		input.CustomerId,
		input.ExternalId,
		input.ItemSpecificationId,
		input.OfferId,
		input.PointOfSaleId,
		input.BillingId,
		input.ExtraData,
		input.OfferedAmount,
		0,
	)
	if err != nil {
		return &domain.Order{}, err
	}

	order.Items = input.Items
	var totalAmount int64
	var quantity int
	for _, item := range input.Items {
		totalAmount += item.UnitAmount * int64(item.Quantity)
		quantity += item.Quantity
	}
	order.OfferedAmount = totalAmount
	order.TotalQuantity = quantity

	if input.WompiIdPayment == "" {
		order.State = "Created"
	} else {
		order.State = "Pending"
	}
	order.WompiIdPayment = input.WompiIdPayment

	for _, orderItem := range input.Items {
		itemSpec, err := s.itemSpecRepo.GetById(ctx, orderItem.ItemSpecificationId)
		if err != nil {
			return &domain.Order{}, fmt.Errorf("error getting item specification for update %s: %w", orderItem.ItemSpecificationId, err)
		}

		err = itemSpec.CheckAndUpdateAvailabilityState()
		if err != nil {
			return &domain.Order{}, fmt.Errorf("error updating availability state: %w", err)
		}

		err = s.itemSpecRepo.Save(ctx, itemSpec)
		if err != nil {
			return &domain.Order{}, fmt.Errorf("error saving updated item specification: %w", err)
		}
	}

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

	return s.repo.SaveOrder(ctx, order)
}

func (s *orderService) UpdateOrderState(ctx context.Context, orderId string, state string) error {
	start := time.Now()
	s.serviceLogger.LogServiceStart(ctx, "UpdateOrderState", map[string]interface{}{
		"order_id":  orderId,
		"new_state": state,
	})

	order, err := s.repo.GetIdOrder(ctx, orderId)
	if err != nil {
		s.serviceLogger.LogServiceError(ctx, "UpdateOrderState", err, map[string]interface{}{
			"order_id": orderId,
			"error":    "failed_to_get_order",
		})
		return err
	}

	oldState := order.State
	order.State = state

	err = s.repo.SaveOrder(ctx, order)
	if err != nil {
		s.serviceLogger.LogServiceError(ctx, "UpdateOrderState", err, map[string]interface{}{
			"order_id":  orderId,
			"old_state": oldState,
			"new_state": state,
			"error":     "failed_to_save_order",
		})
		return err
	}

	s.serviceLogger.LogWorkflow(ctx, "OrderStateUpdate", state, map[string]interface{}{
		"order_id":    orderId,
		"old_state":   oldState,
		"new_state":   state,
		"customer_id": order.CustomerId,
		"amount":      order.OfferedAmount,
	})

	s.serviceLogger.LogServiceEnd(ctx, "UpdateOrderState", time.Since(start), map[string]interface{}{
		"order_id":  orderId,
		"old_state": oldState,
		"new_state": state,
		"success":   true,
	})

	return nil
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

func (s *orderService) GetPaginatedOrdersWithDetails(ctx context.Context, params domain.PaginationParams, filters map[string]string) (*domain.PaginatedOrdersResponse, error) {
	if params.PageSize < 1 {
		params.PageSize = 10
	}
	if params.PageSize > 100 {
		params.PageSize = 100
	}

	if params.PointOfSaleId == "" {
		return nil, fmt.Errorf("pointOfSaleId is required")
	}
	
	ordersResult, err := s.repo.GetOrdersPaginated(ctx, params, filters)
	if err != nil {
		return nil, fmt.Errorf("error al obtener órdenes paginadas: %w", err)
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
		TotalCount: ordersResult.TotalCount,
	}, nil
}

func (s *orderService) GetOrdersBillingByID(ctx context.Context, id string) ([]domain.Order, error) {
	order, err := s.repo.GetOrdersBillingByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return order, nil
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

	// Generar PDF
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 14)
	pdf.Cell(0, 10, cp1252("Resumen de Órdenes Aprobadas"))
	pdf.Ln(12)

	pdf.SetFont("Arial", "B", 10)
	pdf.CellFormat(50, 7, "OrderId", "1", 0, "", false, 0, "")
	pdf.CellFormat(55, 7, "Producto", "1", 0, "", false, 0, "")
	pdf.CellFormat(20, 7, "Monto", "1", 0, "", false, 0, "")
	pdf.CellFormat(60, 7, "CustomerId", "1", 0, "", false, 0, "")
	pdf.Ln(-1)

	pdf.SetFont("Arial", "", 9)
	for _, order := range approvedOrders {
		x := pdf.GetX()
		y := pdf.GetY()

		orderIdLines := pdf.SplitLines([]byte(order.OrderId), 50)
		productLines := pdf.SplitLines([]byte(cp1252(order.ExtraData)), 55)

		maxLines := len(orderIdLines)
		if len(productLines) > maxLines {
			maxLines = len(productLines)
		}

		rowHeight := 6.0
		totalHeight := float64(maxLines) * rowHeight

		for len(orderIdLines) < maxLines {
			orderIdLines = append(orderIdLines, []byte{})
		}
		for len(productLines) < maxLines {
			productLines = append(productLines, []byte{})
		}

		for i := 0; i < maxLines; i++ {
			pdf.SetXY(x, y+float64(i)*rowHeight)
			pdf.CellFormat(50, rowHeight, string(orderIdLines[i]), "", 0, "", false, 0, "")

			pdf.SetXY(x+50, y+float64(i)*rowHeight)
			pdf.CellFormat(55, rowHeight, string(productLines[i]), "", 0, "", false, 0, "")
		}

		pdf.Rect(x, y, 50, totalHeight, "D")
		pdf.Rect(x+50, y, 55, totalHeight, "D")

		pdf.SetXY(x+105, y)
		p := message.NewPrinter(language.Spanish)
		formattedAmount := p.Sprintf("%d", order.OfferedAmount)
		pdf.CellFormat(20, totalHeight, formattedAmount, "1", 0, "", false, 0, "")
		pdf.CellFormat(60, totalHeight, order.CustomerId, "1", 0, "", false, 0, "")

		pdf.Ln(totalHeight)
	}

	var buf bytes.Buffer
	err = pdf.Output(&buf)
	if err != nil {
		return fmt.Errorf("error generando el PDF: %w", err)
	}

	subject := "Resumen de Órdenes Aprobadas Adjunto"
	body := `<html><body><p>Estimado(a) administrador(a),</p><p>Adjunto a este correo, encontrará el resumen detallado de todas las órdenes aprobadas.</p></body></html>`
	attachmentName := "ordenes_aprobadas.pdf"

	err = s.emailService.NotifyAdminApprovedOrdersWithAttachment(ctx, adminEmail, subject, body, attachmentName, buf.Bytes())
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

func cp1252(s string) string {
	encoded, err := charmap.Windows1252.NewEncoder().String(s)
	if err != nil {
		log.Fatalf("encoding error: %v", err)
	}
	return encoded
}
