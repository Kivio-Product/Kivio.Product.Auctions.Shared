package services

import (
	"context"
	"fmt"
	"net/url"
	"strconv"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/billing"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
	paymentDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/payment"

	billingHelpers "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/billing/helpers"
	paymentConfirmation "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/billing/payment_confirmation"
	ecommerceService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/ecommerce"

	billingInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/billing"
	orderInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/order"
)

type BillingService interface {
	CreateBilling(ctx context.Context, provider, posId, customerId string, customer *domain.Customer) (*domain.Billing, error)
	GetAllBillings(ctx context.Context) ([]domain.Billing, error)
	GetBillingById(ctx context.Context, id string) (*domain.Billing, error)
	GetBillingByIdWithExternalData(ctx context.Context, id string) (*domain.Billing, error)
	GetBillingByTransactionId(ctx context.Context, id string) (*domain.Billing, error)
	ConfirmPayUResponse(ctx context.Context, res *paymentDomain.ConfirmationResponse, secretKey string) error
	ConfirmWompiResponse(ctx context.Context, body []byte) error
	GetPaginatedBillingsWithDetails(ctx context.Context, params orderDomain.PaginationParams, filters map[string]string) (*domain.PaginatedBillingDetailsResponse, error)
	GetBillingReferenceByOrderId(ctx context.Context, orderId string) (string, error)
}

type billingService struct {
	repo             billingInfrastructure.BillingRepository
	billingFactory   domain.BillingFactory
	orderRepo        orderInfrastructure.OrderRepository
	payuHandler      *paymentConfirmation.PayUConfirmationHandler
	wompiHandler     *paymentConfirmation.WompiConfirmationHandler
	ecommerceSvc     ecommerceService.EcommerceService
	ecommerceCredSvc ecommerceService.EcommerceCredentialsService
}

func NewBillingService(
	repo billingInfrastructure.BillingRepository,
	billingFactory domain.BillingFactory,
	orderRepo orderInfrastructure.OrderRepository,
	payuHandler *paymentConfirmation.PayUConfirmationHandler,
	wompiHandler *paymentConfirmation.WompiConfirmationHandler,
	ecommerceSvc ecommerceService.EcommerceService,
	ecommerceCredSvc ecommerceService.EcommerceCredentialsService,
) BillingService {
	return &billingService{
		repo:             repo,
		billingFactory:   billingFactory,
		orderRepo:        orderRepo,
		payuHandler:      payuHandler,
		wompiHandler:     wompiHandler,
		ecommerceSvc:     ecommerceSvc,
		ecommerceCredSvc: ecommerceCredSvc,
	}
}

func (s *billingService) CreateBilling(ctx context.Context, provider, posId, customerId string, customer *domain.Customer) (*domain.Billing, error) {
	invoiceConfig := billingHelpers.GetInvoiceConfigFromEnv()
	billing, err := s.billingFactory.CreateBilling(provider, posId, customer, invoiceConfig)
	if err != nil {
		return nil, err
	}

	billing.CustomerId = &customerId

	err = s.repo.SaveBilling(ctx, billing)
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

func (s *billingService) GetPaginatedBillingsWithDetails(ctx context.Context, params orderDomain.PaginationParams, filters map[string]string) (*domain.PaginatedBillingDetailsResponse, error) {
	if params.PageSize < 1 {
		params.PageSize = 10
	}
	if params.PageSize > 100 {
		params.PageSize = 100
	}

	result, err := s.repo.GetOrderBillingPaginated(ctx, params, filters)
	if err != nil {
		return nil, fmt.Errorf("error al obtener ordenes facturadas paginadas: %w", err)
	}

	billingsMap := make(map[string]*domain.BillingDetailResponse)

	for _, billing := range result.Billings {
		orders, _ := s.orderRepo.GetOrdersBillingByID(ctx, billing.Id)

		if _, exists := billingsMap[billing.Id]; !exists {
			billingsMap[billing.Id] = &domain.BillingDetailResponse{
				BillId:        billing.Id,
				TransactionId: billing.TransactionId,
				State:         billing.State,
				Provider:      billing.Provider,
				PayloadType:   billing.PayloadType,
				CreatedAt:     billing.CreatedAt,
				ConfirmedAt:   billing.ConfirmedAt,
				UserEmail:     *billing.CustomerId,
				Orders:        []domain.BillOrder{},
			}
		}

		for _, order := range orders {
			billOrder := domain.BillOrder{
				OfferId:     order.OfferId,
				ItemName:    order.ExtraData,
				OrderAmount: order.OfferedAmount,
			}

			billingsMap[billing.Id].Orders = append(billingsMap[billing.Id].Orders, billOrder)
		}
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

func (s *billingService) GetBillingByIdWithExternalData(ctx context.Context, id string) (*domain.Billing, error) {
	billing, err := s.repo.GetBillingByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if billing.ExternalId == "" {
		fmt.Printf("[BillingService] Billing %s has no ExternalId, returning as-is\n", id)
		return billing, nil
	}

	orders, err := s.orderRepo.GetOrdersBillingByID(ctx, billing.Id)
	if err != nil || len(orders) == 0 {
		fmt.Printf("[BillingService] Could not get orders for billing %s: %v, returning billing as-is\n", id, err)
		return billing, nil
	}

	posID := orders[0].PointOfSaleId

	credentials, err := s.ecommerceCredSvc.GetCredentials(ctx, posID)
	if err != nil {
		fmt.Printf("[BillingService] Could not get ecommerce credentials for POS %s: %v, returning billing as-is\n", posID, err)
		return billing, nil
	}

	externalOrderID, err := strconv.Atoi(billing.ExternalId)
	if err != nil {
		fmt.Printf("[BillingService] Invalid ExternalId format %s: %v, returning billing as-is\n", billing.ExternalId, err)
		return billing, nil
	}

	ecommerceOrder, err := s.ecommerceSvc.GetOrderByID(ctx, credentials.ApiURL, credentials.ApiKey, externalOrderID)
	if err != nil {
		fmt.Printf("[BillingService] Could not get order %d from ecommerce: %v, returning billing as-is\n", externalOrderID, err)
		return billing, nil
	}

	if ecommerceOrder.SiigoInvoicePublicURL != "" && ecommerceOrder.SiigoInvoicePublicURL != "null" {
		fmt.Printf("[BillingService] Found Siigo invoice URL from ecommerce: %s\n", ecommerceOrder.SiigoInvoicePublicURL)

		if billing.SiigoInvoiceURL != "" {
			updatedURL := s.updateInvoiceURLParameter(billing.SiigoInvoiceURL, ecommerceOrder.SiigoInvoicePublicURL)
			billing.SiigoInvoiceURL = updatedURL
			fmt.Printf("[BillingService] Updated billing SiigoInvoiceURL to: %s\n", updatedURL)

			err = s.repo.UpdateBilling(ctx, billing)
			if err != nil {
				fmt.Printf("[BillingService] WARNING: Failed to update billing %s with new invoice URL: %v\n", id, err)
			} else {
				fmt.Printf("[BillingService] Successfully updated billing %s with new invoice URL\n", id)
			}
		}
	} else {
		fmt.Printf("[BillingService] Siigo invoice URL is null or empty in ecommerce order %d\n", externalOrderID)
	}

	return billing, nil
}

func (s *billingService) updateInvoiceURLParameter(currentURL, siigoInvoicePublicURL string) string {
	parsedURL, err := url.Parse(currentURL)
	if err != nil {
		fmt.Printf("[BillingService] Error parsing URL %s: %v, returning as-is\n", currentURL, err)
		return currentURL
	}

	query := parsedURL.Query()
	query.Set("invoiceUrl", siigoInvoicePublicURL)
	parsedURL.RawQuery = query.Encode()

	return parsedURL.String()
}

func (s *billingService) GetBillingByTransactionId(ctx context.Context, id string) (*domain.Billing, error) {
	billing, err := s.repo.GetBillingByTransactionID(ctx, id)
	if err != nil {
		return nil, err
	}
	return billing, nil
}

func (s *billingService) GetBillingReferenceByOrderId(ctx context.Context, orderId string) (string, error) {
	order, err := s.orderRepo.GetIdOrder(ctx, orderId)
	if err != nil {
		return "", fmt.Errorf("error obteniendo Order: %w", err)
	}

	if order.BillingId != "" {
		return order.BillingId, nil
	}

	return "", fmt.Errorf("no se encontró billing para el orderId: %s", orderId)
}

func (s *billingService) ConfirmPayUResponse(ctx context.Context, res *paymentDomain.ConfirmationResponse, secretKey string) error {
	return s.payuHandler.HandleConfirmation(ctx, res, secretKey)
}

func (s *billingService) ConfirmWompiResponse(ctx context.Context, body []byte) error {
	return s.wompiHandler.HandleConfirmation(ctx, body)
}
