package invoice

import (
	"context"
	"fmt"
	"time"

	applicationLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/logging"
	strategyApp "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/strategy"
	billingDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/billing"
	invoiceDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/invoice"
	"github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/logging"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
	siigoClient "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/api/siigo"
	infrastructureLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/logging"
	itemSpecInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/item_specification"
)

type InvoiceService interface {
	CreateInvoiceForOrders(ctx context.Context, billingID string, orders []*orderDomain.Order, customer *billingDomain.Customer, invoiceConfig *billingDomain.InvoiceConfig, posName string) (*invoiceDomain.SiigoInvoiceResponse, error)
}

type invoiceService struct {
	siigoClient           siigoClient.SiigoClient
	invoiceFactory        invoiceDomain.InvoiceFactory
	serviceLogger         *applicationLogging.ServiceLogger
	eventLogger           *logging.DomainEventLogger
	invoiceStrategyFactory *strategyApp.InvoiceStrategyFactory
	itemSpecRepo          itemSpecInfrastructure.ItemSpecificationRepository
}

func NewInvoiceService(
	siigoClient siigoClient.SiigoClient,
	invoiceFactory invoiceDomain.InvoiceFactory,
	invoiceStrategyFactory *strategyApp.InvoiceStrategyFactory,
	itemSpecRepo itemSpecInfrastructure.ItemSpecificationRepository,
) InvoiceService {
	loggerRepo := infrastructureLogging.GetLoggerRepository()
	serviceLogger := applicationLogging.NewServiceLogger(loggerRepo, "InvoiceService")
	eventLogger := logging.NewDomainEventLogger(loggerRepo.GetLogger())

	return &invoiceService{
		siigoClient:            siigoClient,
		invoiceFactory:         invoiceFactory,
		serviceLogger:          serviceLogger,
		eventLogger:            eventLogger,
		invoiceStrategyFactory: invoiceStrategyFactory,
		itemSpecRepo:           itemSpecRepo,
	}
}

func (s *invoiceService) CreateInvoiceForOrders(ctx context.Context, billingID string, orders []*orderDomain.Order, customer *billingDomain.Customer, invoiceConfig *billingDomain.InvoiceConfig, posName string) (*invoiceDomain.SiigoInvoiceResponse, error) {
	start := time.Now()

	orderIds := make([]string, len(orders))
	var totalAmountSum float64
	for i, order := range orders {
		orderIds[i] = order.OrderId
		totalAmountSum += float64(order.OfferedAmount)
	}

	s.serviceLogger.LogServiceStart(ctx, "CreateInvoiceForOrders", map[string]interface{}{
		"billing_id":    billingID,
		"order_count":   len(orders),
		"order_ids":     orderIds,
		"customer_id":   customer.Identification,
		"customer_name": customer.Name,
		"pos_name":      posName,
		"total_amount":  totalAmountSum,
	})

	if len(orders) == 0 {
		err := fmt.Errorf("no orders provided for invoice creation")
		s.serviceLogger.LogServiceError(ctx, "CreateInvoiceForOrders", err, map[string]interface{}{
			"billing_id": billingID,
			"error":      "no_orders_provided",
		})
		return nil, err
	}

	firstOrder := orders[0]
	posID := firstOrder.PointOfSaleId

	// Determinar el source de los items consultando itemSpec
	// Si todos son del mismo source, usar el strategy correspondiente
	var itemSources []string
	for _, order := range orders {
		itemSpec, err := s.itemSpecRepo.GetById(ctx, order.ItemSpecificationId)
		if err != nil {
			s.serviceLogger.LogServiceError(ctx, "CreateInvoiceForOrders", err, map[string]interface{}{
				"order_id": order.OrderId,
				"error":    "failed_to_get_itemspec",
			})
			return nil, fmt.Errorf("error getting itemSpec for order %s: %w", order.OrderId, err)
		}
		itemSources = append(itemSources, string(itemSpec.GetSource()))
	}

	// Obtener el strategy apropiado basado en las integraciones y source de items
	invoiceStrategy, err := s.invoiceStrategyFactory.GetStrategyForOrders(ctx, posID, itemSources)
	if err != nil {
		s.serviceLogger.LogServiceError(ctx, "CreateInvoiceForOrders", err, map[string]interface{}{
			"billing_id": billingID,
			"pos_id":     posID,
			"error":      "failed_to_get_invoice_strategy",
		})
		return nil, fmt.Errorf("error getting invoice strategy: %w", err)
	}

	s.serviceLogger.LogWorkflow(ctx, "InvoiceGeneration", "UsingStrategy", map[string]interface{}{
		"strategy_type": invoiceStrategy.GetInvoiceType(),
		"billing_id":    billingID,
		"pos_id":        posID,
		"order_count":   len(orders),
	})

	// Delegar la creación de factura/orden al strategy
	response, err := invoiceStrategy.CreateInvoiceForOrders(ctx, billingID, orders, customer, invoiceConfig, posName)
	if err != nil {
		s.serviceLogger.LogServiceError(ctx, "CreateInvoiceForOrders", err, map[string]interface{}{
			"billing_id":    billingID,
			"strategy_type": invoiceStrategy.GetInvoiceType(),
			"error":         "strategy_execution_failed",
		})
		return nil, fmt.Errorf("error executing invoice strategy: %w", err)
	}

	s.serviceLogger.LogServiceEnd(ctx, "CreateInvoiceForOrders", time.Since(start), map[string]interface{}{
		"billing_id":    billingID,
		"strategy_type": invoiceStrategy.GetInvoiceType(),
		"order_count":   len(orders),
		"success":       true,
	})

	return response, nil
}
