package services

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/billing"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
	paymentDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/payment"

	emailService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/email"

	billingInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/billing"
	itemInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/item"
	itemSpecInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/item_specification"
	orderInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/order"
)

type BillingService interface {
	CreateBilling(ctx context.Context, provider string, orderIds []string) (*domain.Billing, error)
	GetAllBillings(ctx context.Context) ([]domain.Billing, error)
	GetBillingById(ctx context.Context, id string) (*domain.Billing, error)
	GetAllBillingsWithDetail(ctx context.Context) ([]domain.BillingDetailResponse, error)
	ConfirmPayUResponse(ctx context.Context, res *paymentDomain.ConfirmationResponse, secretKey string) error
	GetPaginatedBillingsWithDetails(ctx context.Context, params orderDomain.PaginationParams) (*domain.PaginatedBillingDetailsResponse, error)
}

type billingService struct {
	repo           billingInfrastructure.BillingRepository
	billingFactory domain.BillingFactory
	orderRepo      orderInfrastructure.OrderRepository
	itemSpecRepo   itemSpecInfrastructure.ItemSpecificationRepository
	itemRepo       itemInfrastructure.ItemRepository
	emailService   emailService.EmailService
}

func NewBillingService(
	repo billingInfrastructure.BillingRepository,
	billingFactory domain.BillingFactory,
	orderRepo orderInfrastructure.OrderRepository,
	itemSpecRepo itemSpecInfrastructure.ItemSpecificationRepository,
	itemRepo itemInfrastructure.ItemRepository,
	emailService emailService.EmailService,
) BillingService {
	return &billingService{
		repo:           repo,
		billingFactory: billingFactory,
		orderRepo:      orderRepo,
		itemSpecRepo:   itemSpecRepo,
		itemRepo:       itemRepo,
		emailService:   emailService,
	}
}

func (s *billingService) CreateBilling(ctx context.Context, provider string, orderIds []string) (*domain.Billing, error) {
	billing, err := s.billingFactory.CreateBilling(provider)
	if err != nil {
		return nil, err
	}

	order, err := s.orderRepo.GetIdOrder(ctx, orderIds[0])
	if err != nil {
		return nil, err
	}

	if order != nil {
		customerId := order.CustomerId
		billing.CustomerId = &customerId
	} else {
		return nil, fmt.Errorf("no se encontró la orden con ID: %s", orderIds[0])
	}

	err = s.repo.SaveBillingWithOrders(ctx, billing, orderIds)
	if err != nil {
		return nil, err
	}

	return billing, nil
}

func (s *billingService) GetAllBillings(ctx context.Context) ([]domain.Billing, error) {
	billings, err := s.repo.GetAllBillings(ctx)
	if err != nil {
		return nil, err
	}
	return billings, nil
}

func (s *billingService) GetAllBillingsWithDetail(ctx context.Context) ([]domain.BillingDetailResponse, error) {
	billingOrders, err := s.repo.GetAllOrderBillings(ctx)
	if err != nil {
		return nil, err
	}

	billingsMap := make(map[string]*domain.BillingDetailResponse)

	for _, billingOrder := range billingOrders {
		order, err := s.orderRepo.GetIdOrder(ctx, billingOrder.OrderId)
		if err != nil {
			return nil, err
		}

		billing, err := s.repo.GetBillingByID(ctx, billingOrder.BillingId)
		if err != nil {
			return nil, err
		}

		itemSpec, err := s.itemSpecRepo.GetById(ctx, order.ItemSpecificationId)
		if err != nil {
			return nil, err
		}

		item, err := s.itemRepo.GetItemById(ctx, itemSpec.ItemId)
		if err != nil {
			return nil, err
		}

		billOrder := domain.BillOrder{
			OfferId:         order.OfferId,
			ItemName:        item.Name,
			ItemDescription: item.Description,
			OrderAmount:     order.OfferedAmount,
			ItemPrice:       itemSpec.Amount,
		}

		if _, exists := billingsMap[billing.Id]; !exists {
			billingsMap[billing.Id] = &domain.BillingDetailResponse{
				BillId:        billing.Id,
				TransactionId: billing.TransactionId,
				State:         billing.State,
				Provider:      billing.Provider,
				PayloadType:   billing.PayloadType,
				CreatedAt:     billing.CreatedAt,
				ConfirmedAt:   billing.ConfirmedAt,
				UserEmail:     order.CustomerId,
				Orders:        []domain.BillOrder{},
			}
		}

		billingsMap[billing.Id].Orders = append(billingsMap[billing.Id].Orders, billOrder)
	}

	billingDetails := make([]domain.BillingDetailResponse, 0, len(billingsMap))
	for _, detail := range billingsMap {
		billingDetails = append(billingDetails, *detail)
	}

	return billingDetails, nil
}

func (s *billingService) GetPaginatedBillingsWithDetails(ctx context.Context, params orderDomain.PaginationParams) (*domain.PaginatedBillingDetailsResponse, error) {
	if params.PageSize < 1 {
		params.PageSize = 10
	}
	if params.PageSize > 100 {
		params.PageSize = 100
	}

	result, err := s.repo.GetOrderBillingPaginated(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("error al obtener ordenes facturadas paginadas: %w", err)
	}

	billingsMap := make(map[string]*domain.BillingDetailResponse)

	for _, billingOrder := range result.Billings {
		order, err := s.orderRepo.GetIdOrder(ctx, billingOrder.OrderId)
		if err != nil {
			return nil, err
		}

		billing, err := s.repo.GetBillingByID(ctx, billingOrder.BillingId)
		if err != nil {
			return nil, err
		}

		itemSpec, err := s.itemSpecRepo.GetById(ctx, order.ItemSpecificationId)
		if err != nil {
			return nil, err
		}

		item, err := s.itemRepo.GetItemById(ctx, itemSpec.ItemId)
		if err != nil {
			return nil, err
		}

		billOrder := domain.BillOrder{
			OfferId:         order.OfferId,
			ItemName:        item.Name,
			ItemDescription: item.Description,
			OrderAmount:     order.OfferedAmount,
			ItemPrice:       itemSpec.Amount,
		}

		if _, exists := billingsMap[billing.Id]; !exists {
			billingsMap[billing.Id] = &domain.BillingDetailResponse{
				BillId:        billing.Id,
				TransactionId: billing.TransactionId,
				State:         billing.State,
				Provider:      billing.Provider,
				PayloadType:   billing.PayloadType,
				CreatedAt:     billing.CreatedAt,
				ConfirmedAt:   billing.ConfirmedAt,
				UserEmail:     order.CustomerId,
				Orders:        []domain.BillOrder{},
			}
		}

		billingsMap[billing.Id].Orders = append(billingsMap[billing.Id].Orders, billOrder)
	}

	billingDetails := make([]domain.BillingDetailResponse, 0, len(billingsMap))
	for _, detail := range billingsMap {
		billingDetails = append(billingDetails, *detail)
	}

	return &domain.PaginatedBillingDetailsResponse{
		Billings:   billingDetails,
		NextToken:  result.NextToken,
		TotalCount: result.TotalCount,
	}, nil
}

func (s *billingService) GetBillingById(ctx context.Context, id string) (*domain.Billing, error) {
	billing, err := s.repo.GetBillingByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return billing, nil
}

func (s *billingService) GetOrdersByBillingId(ctx context.Context, id string) ([]domain.BillingByOrder, error) {
	billing, err := s.repo.GetOrdersBillingByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return billing, nil
}

func (s *billingService) ConfirmPayUResponse(ctx context.Context, res *paymentDomain.ConfirmationResponse, secretKey string) error {
	fmt.Println("Iniciando ConfirmPayUResponse")

	if res == nil || res.ReferenceSale == "" {
		fmt.Println("Error: confirmación nula o referencia de venta vacía")
		return errors.New("referencia inválida")
	}

	fmt.Printf("Datos de confirmación: MerchantId=%s, ReferenceSale=%s, Value=%s, Currency=%s, StatePol=%d\n",
		res.MerchantId, res.ReferenceSale, res.ValueStr, res.Currency, res.StatePol)

	isValid := validatePayUSignature(secretKey, res.MerchantId, res.ReferenceSale, res.ValueStr, res.Currency, res.StatePol, res.Sign)
	if !isValid {
		fmt.Printf("Error: firma inválida para transacción %s\n", res.ReferenceSale)
		return errors.New("firma inválida")
	}

	fmt.Println("Firma validada correctamente")

	billingId := res.ReferenceSale
	fmt.Printf("Buscando facturación con ID: %s\n", billingId)

	billing, err := s.repo.GetBillingByID(ctx, billingId)
	if err != nil {
		fmt.Printf("Error: no se encontró facturación con ID: %s - %v\n", billingId, err)
		return fmt.Errorf("no se encontró facturación con ID: %s", billingId)
	}

	fmt.Printf("Facturación encontrada: %+v\n", billing)

	state := map[int]string{
		4:   "Approved",
		6:   "Rejected",
		104: "Error",
		7:   "Pending",
	}[res.StatePol]

	fmt.Printf("Estado de la transacción: %d -> %s\n", res.StatePol, state)

	billing.State = state
	billing.PayloadType = res.PaymentMethod
	billing.TransactionId = res.TransactionId
	billing.ConfirmedAt = time.Now()

	fmt.Printf("Actualizando facturación: State=%s, PayloadType=%s, TransactionId=%s, ConfirmedAt=%v\n",
		billing.State, billing.PayloadType, billing.TransactionId, billing.ConfirmedAt)

	err = s.repo.UpdateBilling(ctx, billing)
	if err != nil {
		fmt.Printf("Error al actualizar la facturación: %v\n", err)
		return fmt.Errorf("error al actualizar la facturación: %v", err)
	}

	orders, err := s.repo.GetOrdersBillingByID(ctx, billingId)

	if err != nil {
		fmt.Printf("no se encontraron ordenes de facturas con ID: %s\n", billingId)

		return fmt.Errorf("no se encontraron ordenes de facturas con ID: %s", billingId)
	}

	var orderIDs []string
	for _, order := range orders {
		orderIDs = append(orderIDs, order.OrderId)
	}

	var validOrders []*orderDomain.Order

	for _, id := range orderIDs {
		order, err := s.orderRepo.GetIdOrder(ctx, id)
		if err == nil {
			validOrders = append(validOrders, order)
		}
	}

	if len(validOrders) == 0 {
		return fmt.Errorf("no se encontró ninguna orden válida en: %v", orderIDs)
	}

	if res.Extra1 == "Quick offer" {

		for _, order := range validOrders {

			itemSpec, err := s.itemSpecRepo.GetById(ctx, order.ItemSpecificationId)
			if err != nil {
				fmt.Printf("no se encontro el itemSpec con Id: %s\n", order.ItemSpecificationId)
			}

			item, err := s.itemRepo.GetItemById(ctx, itemSpec.ItemId)
			if err != nil {
				fmt.Printf("no se encontro el item con Id: %s\n", order.ItemSpecificationId)
			}
			var typer = ""

			switch state {
			case "Approved":
				order.State = "Approved"
				itemSpec.Availability--
				typer = "Quick"
			case "Rejected", "Error":
				order.State = "Rejected"
			default:
				continue
			}

			err = s.orderRepo.UpdateOrder(ctx, order)
			if err != nil {
				return fmt.Errorf("no se pudo actualizar la orden %s: %v", order.OrderId, err)
			}

			err = s.itemSpecRepo.UpdateItemSpec(ctx, itemSpec)
			if err != nil {
				return fmt.Errorf("no se pudo actualizar el item specification %s: %v", order.ItemSpecificationId, err)
			}

			err = s.emailService.NotifyOrder(ctx, typer, order, itemSpec, item)
			if err != nil {
				fmt.Printf("No se puedo enviar el correo: %s\n", err)
			}
		}
	}
	if res.Extra1 == "Regular auction" {

		for _, order := range validOrders {
			switch state {
			case "Approved":
				order.State = "Pending"
			case "Rejected", "Error":
				order.State = "Rejected"
			default:
				continue
			}

			err := s.orderRepo.UpdateOrder(ctx, order)
			if err != nil {
				return fmt.Errorf("no se pudo actualizar la orden %s: %v", order.OrderId, err)
			}
		}
	}

	fmt.Println("Facturación actualizada correctamente")
	return nil
}

func validatePayUSignature(secretKey, merchantId, referenceSale string, valueStr string, currency string, statePol int, incomingSignature string) bool {

	value, _ := strconv.ParseFloat(valueStr, 64)
	fmt.Printf("Valor original: %s, Convertido a float: %f\n", valueStr, value)

	var formattedValue string
	if math.Mod(value*100, 10) == 0 {
		formattedValue = fmt.Sprintf("%.1f", value)
	} else {
		formattedValue = fmt.Sprintf("%.2f", value)
	}

	fmt.Printf("Valor formateado: %s\n", formattedValue)

	signatureString := fmt.Sprintf("%s~%s~%s~%s~%s~%d",
		secretKey, merchantId, referenceSale, formattedValue, currency, statePol)

	fmt.Printf("String para firma (ocultando clave secreta): [SECRET]~%s~%s~%s~%s~%d\n",
		merchantId, referenceSale, formattedValue, currency, statePol)

	hash := md5.Sum([]byte(signatureString))
	expected := hex.EncodeToString(hash[:])

	fmt.Printf("Firma esperada: %s\n", expected)
	fmt.Printf("Firma recibida: %s\n", incomingSignature)
	fmt.Printf("¿Las firmas coinciden? %t\n", strings.EqualFold(expected, incomingSignature))

	return strings.EqualFold(expected, incomingSignature)
}
