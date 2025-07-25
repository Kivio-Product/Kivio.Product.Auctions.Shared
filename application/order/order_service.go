package services

import (
	"context"
	"fmt"
	"os"
	"sync"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
	itemInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/item"
	itemSpecInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/item_specification"
	orderInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/order"

	"bytes"

	billing "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/billing"
	emailservices "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/email"
	offerService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/offer"
	payment "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/payment"
	paymentDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/payment"
	"github.com/jung-kurt/gofpdf"
	"golang.org/x/text/message"
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
	repo           orderInfrastructure.OrderRepository
	orderFactory   domain.OrderFactory
	itemSpecRepo   itemSpecInfrastructure.ItemSpecificationRepository
	itemRepo       itemInfrastructure.ItemRepository
	emailService   emailservices.EmailServiceInterface
	offerService   offerService.IOfferService
	wompiService   payment.WompiService
	billingService billing.BillingService
}

func NewOrderService(repo orderInfrastructure.OrderRepository, orderFactory domain.OrderFactory, itemSpecRepo itemSpecInfrastructure.ItemSpecificationRepository, itemRepo itemInfrastructure.ItemRepository, emailService emailservices.EmailServiceInterface, offerService offerService.IOfferService, wompiService payment.WompiService, billingService billing.BillingService) OrderService {
	return &orderService{repo: repo, orderFactory: orderFactory, itemSpecRepo: itemSpecRepo, itemRepo: itemRepo, emailService: emailService, offerService: offerService, wompiService: wompiService, billingService: billingService}
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

func toCents(amount float64) int64 {
	return int64(amount * 100)
}

func (s *orderService) UpdateOrder(ctx context.Context, input domain.OrderInput) error {
	order, err := s.repo.GetIdOrder(ctx, input.OrderId)
	if err != nil {
		return err
	}

	amountInCents := input.OfferedAmount
	if amountInCents < 1000000 {
		amountInCents = toCents(float64(input.OfferedAmount))
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

	if input.IsWinner {
		offer, err := s.offerService.GetOfferById(ctx, order.OfferId)
		if err != nil {
			return err
		}
		if offer.Type == "Regular auction" && order.WompiIdPayment != "" {
			billingReference, err := s.billingService.GetBillingReferenceByOrderId(ctx, order.OrderId)
			if err != nil {
				return fmt.Errorf("error obteniendo la referencia de facturación: %w", err)
			}

			wompiReq := &paymentDomain.WompiTransactionRequest{
				AmountInCents:   amountInCents,
				Currency:        "COP",
				CustomerEmail:   order.CustomerId,
				PaymentSourceId: 0,
				Reference:       billingReference,
				PaymentMethod: &paymentDomain.WompiPaymentMethod{
					Installments: 1,
				},
			}

			var paymentSourceId int64
			_, err = fmt.Sscan(order.WompiIdPayment, &paymentSourceId)
			if err != nil {
				return fmt.Errorf("error convirtiendo WompiIdPayment a int64: %w", err)
			}
			wompiReq.PaymentSourceId = paymentSourceId

			integritySecret := os.Getenv("WOMPI_INTEGRITY_SECRET")
			if integritySecret == "" {
				return fmt.Errorf("WOMPI_INTEGRITY_SECRET no está configurado")
			}
			signatureResp, err := s.wompiService.GenerateIntegritySignature(ctx, billingReference, amountInCents, "COP", integritySecret, nil)
			if err != nil {
				return fmt.Errorf("error generando signature Wompi: %w", err)
			}
			wompiReq.Signature = signatureResp.Signature

			_, err = s.wompiService.CreateTransaction(ctx, wompiReq)
			if err != nil {
				return fmt.Errorf("error creando transacción Wompi: %w", err)
			}
		}
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

	// Generar PDF
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 14) // Título más pequeño
	pdf.Cell(0, 10, "Resumen de Órdenes Aprobadas")
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
		productLines := pdf.SplitLines([]byte(order.ExtraData), 50)
		maxLines := len(orderIdLines)
		if len(productLines) > maxLines {
			maxLines = len(productLines)
		}
		rowHeight := float64(maxLines) * 6
		if len(orderIdLines) == maxLines {
			pdf.MultiCell(50, 6, order.OrderId, "1", "", false)
		} else {
			pdf.CellFormat(50, rowHeight, order.OrderId, "1", 0, "", false, 0, "")
		}
		pdf.SetXY(x+50, y)

		if len(productLines) == maxLines {
			pdf.MultiCell(55, 6, order.ExtraData, "1", "", false)
		} else {
			pdf.CellFormat(50, rowHeight, order.ExtraData, "1", 0, "", false, 0, "")
		}
		pdf.SetXY(x+105, y)
		p := message.NewPrinter(message.MatchLanguage("en"))
		formattedAmount := p.Sprintf("%d", order.OfferedAmount)
		pdf.CellFormat(20, rowHeight, formattedAmount, "1", 0, "", false, 0, "")
		pdf.CellFormat(60, rowHeight, order.CustomerId, "1", 0, "", false, 0, "")
		pdf.Ln(-1)
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
