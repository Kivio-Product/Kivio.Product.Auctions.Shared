package helpers

import (
	"context"
	"fmt"

	pointOfSaleService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/point_of_sale"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
	orderInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/order"
)

type OrderHelper struct {
	orderRepo          orderInfrastructure.OrderRepository
	pointOfSaleService pointOfSaleService.IPosService
}

func NewOrderHelper(
	orderRepo orderInfrastructure.OrderRepository,
	pointOfSaleService pointOfSaleService.IPosService,
) *OrderHelper {
	return &OrderHelper{
		orderRepo:          orderRepo,
		pointOfSaleService: pointOfSaleService,
	}
}

func (h *OrderHelper) GetValidOrdersByBillingID(ctx context.Context, billingID string) ([]*orderDomain.Order, error) {
	orders, err := h.orderRepo.GetOrdersBillingByID(ctx, billingID)
	if err != nil {
		fmt.Printf("no se encontraron ordenes de facturas con ID: %s\n", billingID)
		return nil, fmt.Errorf("no se encontraron ordenes de facturas con ID: %s", billingID)
	}

	var orderIDs []string
	for _, order := range orders {
		orderIDs = append(orderIDs, order.OrderId)
	}

	var validOrders []*orderDomain.Order
	for _, id := range orderIDs {
		order, err := h.orderRepo.GetIdOrder(ctx, id)
		if err == nil {
			validOrders = append(validOrders, order)
		}
	}

	if len(validOrders) == 0 {
		return nil, fmt.Errorf("no se encontró ninguna orden válida en: %v", orderIDs)
	}

	return validOrders, nil
}

func (h *OrderHelper) GetPOSName(ctx context.Context, orders []*orderDomain.Order) (string, string) {
	if len(orders) == 0 {
		return "", ""
	}

	posID := orders[0].PointOfSaleId
	var posName string

	if posID != "" {
		pos, err := h.pointOfSaleService.GetPosById(ctx, posID)
		if err == nil {
			posName = pos.Name
		}
	}

	return posID, posName
}
