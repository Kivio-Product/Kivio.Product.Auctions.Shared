package order_creation

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	billingHelpers "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/billing/helpers"
	customerService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/customer"
	ecommerceService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/ecommerce"
	billingDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/billing"
	itemDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
	itemSpecDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item_specification"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
	ecommerceInfra "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/ecommerce"
	itemSpecInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/item_specification"
)

type EcommerceOrderCreationStrategy struct {
	ecommerceCredSvc ecommerceService.EcommerceCredentialsService
	ecommerceSvc     ecommerceService.EcommerceService
	customerService  customerService.CustomerService
	itemSpecRepo     itemSpecInfrastructure.ItemSpecificationRepository
}

func NewEcommerceOrderCreationStrategy(
	ecommerceCredSvc ecommerceService.EcommerceCredentialsService,
	ecommerceSvc ecommerceService.EcommerceService,
	customerService customerService.CustomerService,
	itemSpecRepo itemSpecInfrastructure.ItemSpecificationRepository,
) *EcommerceOrderCreationStrategy {
	return &EcommerceOrderCreationStrategy{
		ecommerceCredSvc: ecommerceCredSvc,
		ecommerceSvc:     ecommerceSvc,
		customerService:  customerService,
		itemSpecRepo:     itemSpecRepo,
	}
}

func (s *EcommerceOrderCreationStrategy) CreateExternalOrder(
	ctx context.Context,
	billing *billingDomain.Billing,
	orders []*orderDomain.Order,
	item *itemDomain.Item,
	itemSpec *itemSpecDomain.ItemSpecification,
) error {
	if len(orders) == 0 {
		return fmt.Errorf("no orders provided")
	}

	posID := orders[0].PointOfSaleId
	credentials, err := s.ecommerceCredSvc.GetCredentials(ctx, posID)
	if err != nil {
		return fmt.Errorf("error getting ecommerce credentials for POS %s: %w", posID, err)
	}

	fmt.Printf("[EcommerceOrderCreation] Starting order creation for %d orders\n", len(orders))

	customer, err := s.customerService.GetOrCreateCustomer(ctx, billing.Customer.Email)
	if err != nil {
		return fmt.Errorf("error getting or creating customer: %w", err)
	}

	var customerResponse *ecommerceInfra.EcommerceCustomerResponse
	var billingAddressResponse *ecommerceInfra.EcommerceBillingAddressResponse

	if customer.ExternalCustomerID == "" {
		ecommerceCustomer := s.createEcommerceCustomerFromBilling(billing)

		customerResponse, err = s.ecommerceSvc.CreateEcommerceCustomer(ctx, credentials.ApiURL, credentials.ApiKey, ecommerceCustomer)
		if err != nil {
			return fmt.Errorf("error creating customer in ecommerce: %w", err)
		}

		err = s.customerService.UpdateExternalCustomerID(ctx, customer.Email, fmt.Sprintf("%d", customerResponse.ID))
		if err != nil {
			return fmt.Errorf("error updating customer with external ID: %w", err)
		}
	} else {
		customerResponse = &ecommerceInfra.EcommerceCustomerResponse{
			ID: func() int {
				id, _ := strconv.Atoi(customer.ExternalCustomerID)
				return id
			}(),
		}
	}

	if customer.BillingAddressID == "" {
		ecommerceBillingAddress := s.createEcommerceBillingAddressFromBilling(billing)

		billingAddressResponse, err = s.ecommerceSvc.CreateEcommerceBillingAddress(ctx, credentials.ApiURL, credentials.ApiKey, customerResponse.ID, ecommerceBillingAddress)
		if err != nil {
			return fmt.Errorf("error creating billing address in ecommerce: %w", err)
		}

		err = s.customerService.UpdateBillingAddress(ctx, customer.Email, fmt.Sprintf("%d", billingAddressResponse.ID))
		if err != nil {
			return fmt.Errorf("error updating customer with billing address ID: %w", err)
		}
	}

	if customer.ShippingAddressID == "" {
		ecommerceShippingAddress := s.createEcommerceShippingAddressFromBilling(billing)

		shippingAddressResponse, err := s.ecommerceSvc.CreateEcommerceShippingAddress(ctx, credentials.ApiURL, credentials.ApiKey, customerResponse.ID, ecommerceShippingAddress)
		if err != nil {
			return fmt.Errorf("error creating shipping address in ecommerce: %w", err)
		}

		err = s.customerService.UpdateShippingAddress(ctx, customer.Email, fmt.Sprintf("%d", shippingAddressResponse.ID))
		if err != nil {
			return fmt.Errorf("error updating customer with shipping address ID: %w", err)
		}
	}

	productID := s.extractCleanProductID(itemSpec.ItemId)
	fmt.Printf("[EcommerceOrderCreation] Extracted clean product ID: %d from itemSpec.ItemId: %s\n", productID, itemSpec.ItemId)

	ecommerceShoppingCartItem := s.createEcommerceShoppingCartItemFromOrders(orders, customerResponse.ID, productID)

	cartResponse, err := s.ecommerceSvc.CreateEcommerceShoppingCartItem(ctx, credentials.ApiURL, credentials.ApiKey, ecommerceShoppingCartItem)
	if err != nil {
		return fmt.Errorf("error creating shopping cart item in ecommerce: %w", err)
	}

	fmt.Printf("[EcommerceOrderCreation] Shopping cart item created with ID: %d\n", cartResponse.ID)

	var billingAddressID, shippingAddressID int
	if billingAddressResponse != nil {
		billingAddressID = billingAddressResponse.ID
	} else {
		if id, err := strconv.Atoi(customer.BillingAddressID); err == nil {
			billingAddressID = id
		}
	}

	if customer.ShippingAddressID != "" {
		if id, err := strconv.Atoi(customer.ShippingAddressID); err == nil {
			shippingAddressID = id
		}
	} else {
		shippingAddressID = billingAddressID
	}

	ecommerceOrder := s.createEcommerceOrderFromOrders(orders, customerResponse.ID, item, billingAddressID, shippingAddressID)

	orderResponse, err := s.ecommerceSvc.CreateEcommerceSimpleOrder(ctx, credentials.ApiURL, credentials.ApiKey, ecommerceOrder)
	if err != nil {
		return fmt.Errorf("error creating order in ecommerce: %w", err)
	}

	fmt.Printf("[EcommerceOrderCreation] Order created successfully with ID: %d, Order Items: %d, First Item ID: %d\n",
		orderResponse.ID, orderResponse.OrderItemsCount, orderResponse.OrderItemID)

	if orderResponse.OrderItemID > 0 && itemSpec != nil && len(orderResponse.OrderItems) > 0 {
		unitPriceInclTax := float64(itemSpec.Amount)

		firstOrderItem := orderResponse.OrderItems[0]
		originalUnitPriceInclTax := firstOrderItem.UnitPriceInclTax
		originalUnitPriceExclTax := firstOrderItem.UnitPriceExclTax

		fmt.Printf("[EcommerceOrderCreation] Original order item prices - InclTax: %.2f, ExclTax: %.2f\n",
			originalUnitPriceInclTax, originalUnitPriceExclTax)

		totalQuantity := 0
		for _, order := range orders {
			totalQuantity += order.TotalQuantity
		}

		fmt.Printf("[EcommerceOrderCreation] Calculating prices with: UnitPriceInclTax=%.2f, Quantity=%d\n",
			unitPriceInclTax, totalQuantity)

		priceCalc, err := billingHelpers.CalculateOrderItemPrices(
			unitPriceInclTax,
			originalUnitPriceInclTax,
			originalUnitPriceExclTax,
			totalQuantity,
		)
		if err != nil {
			fmt.Printf("[EcommerceOrderCreation] ERROR: Failed to calculate prices: %v\n", err)
			return fmt.Errorf("failed to calculate order item prices: %w", err)
		}

		fmt.Printf("[EcommerceOrderCreation] Calculated prices - UnitPriceInclTax: %.2f, UnitPriceExclTax: %.2f, PriceInclTax: %.2f, PriceExclTax: %.2f\n",
			priceCalc.UnitPriceInclTax, priceCalc.UnitPriceExclTax, priceCalc.PriceInclTax, priceCalc.PriceExclTax)

		orderItem := &ecommerceInfra.EcommerceOrderItem{
			Quantity:         totalQuantity,
			UnitPriceInclTax: priceCalc.UnitPriceInclTax,
			UnitPriceExclTax: priceCalc.UnitPriceExclTax,
			PriceInclTax:     priceCalc.PriceInclTax,
			PriceExclTax:     priceCalc.PriceExclTax,
		}

		fmt.Printf("[EcommerceOrderCreation] Calling UpdateOrderItemPrice with OrderID: %d, ItemID: %d\n", orderResponse.ID, orderResponse.OrderItemID)

		err = s.ecommerceSvc.UpdateOrderItemPrice(ctx, credentials.ApiURL, credentials.ApiKey, orderResponse.ID, orderResponse.OrderItemID, orderItem)
		if err != nil {
			fmt.Printf("[EcommerceOrderCreation] WARNING: Failed to update order item price for order %d, item %d: %v\n", orderResponse.ID, orderResponse.OrderItemID, err)
		} else {
			fmt.Printf("[EcommerceOrderCreation] Order item price updated successfully for order %d, item %d\n", orderResponse.ID, orderResponse.OrderItemID)
		}
	} else if orderResponse.OrderItemID == 0 {
		fmt.Printf("[EcommerceOrderCreation] WARNING: Order created but no order item ID found in response. Cannot update price.\n")
	} else if len(orderResponse.OrderItems) == 0 {
		fmt.Printf("[EcommerceOrderCreation] WARNING: Order created but no order item details in response. Cannot calculate tax rate.\n")
	}

	return nil
}

func (s *EcommerceOrderCreationStrategy) GetOrderType() string {
	return "ecommerce_order"
}

func (s *EcommerceOrderCreationStrategy) extractCleanProductID(itemID string) int {
	cleanID := itemID

	if strings.HasPrefix(itemID, "kivio-ecommerce~") {
		cleanID = strings.TrimPrefix(itemID, "kivio-ecommerce~")
	} else if strings.HasPrefix(itemID, "kivio-ecommerce∼") {
		cleanID = strings.TrimPrefix(itemID, "kivio-ecommerce∼")
	}

	if id, err := strconv.Atoi(cleanID); err == nil {
		return id
	}

	fmt.Printf("[EcommerceOrderCreation] WARNING: Failed to convert cleanID '%s' to int from original itemID '%s'\n", cleanID, itemID)
	return 0
}

func (s *EcommerceOrderCreationStrategy) createEcommerceCustomerFromBilling(billing *billingDomain.Billing) *ecommerceInfra.EcommerceCustomer {
	now := time.Now()

	customer := &ecommerceInfra.EcommerceCustomer{
		Username:     "",
		Email:        billing.Customer.Email,
		FirstName:    "",
		LastName:     "",
		Active:       true,
		CreatedOnUTC: now,
		RoleIDs:      []int{4},
	}

	if len(billing.Customer.Name) > 0 {
		if len(billing.Customer.Name) > 1 {
			customer.FirstName = billing.Customer.Name[0]
			customer.LastName = strings.Join(billing.Customer.Name[1:], " ")
		} else {
			fullName := billing.Customer.Name[0]
			nameParts := strings.Fields(strings.TrimSpace(fullName))
			if len(nameParts) > 1 {
				customer.FirstName = nameParts[0]
				customer.LastName = strings.Join(nameParts[1:], " ")
			} else {
				customer.FirstName = fullName
				customer.LastName = ""
			}
		}
	}

	return customer
}

func (s *EcommerceOrderCreationStrategy) createEcommerceBillingAddressFromBilling(billing *billingDomain.Billing) *ecommerceInfra.EcommerceAddress {
	now := time.Now()

	firstName := ""
	lastName := ""

	if len(billing.Customer.Name) > 0 {
		if len(billing.Customer.Name) > 1 {
			firstName = billing.Customer.Name[0]
			lastName = strings.Join(billing.Customer.Name[1:], " ")
		} else {
			fullName := billing.Customer.Name[0]
			nameParts := strings.Fields(strings.TrimSpace(fullName))
			if len(nameParts) > 1 {
				firstName = nameParts[0]
				lastName = strings.Join(nameParts[1:], " ")
			} else {
				firstName = fullName
				lastName = ""
			}
		}
	}

	address := &ecommerceInfra.EcommerceAddress{
		FirstName:     firstName,
		LastName:      lastName,
		Email:         billing.Customer.Email,
		City:          billing.Customer.Address.City.CityName,
		Address1:      billing.Customer.Address.Address,
		ZipPostalCode: billing.Customer.Address.PostalCode,
		Country:       billing.Customer.Address.City.CountryName,
		Province:      billing.Customer.Address.City.StateName,
		CreatedOnUTC:  now,
		CountryID:     49,
	}

	if len(billing.Customer.Phones) > 0 {
		address.PhoneNumber = billing.Customer.Phones[0].Indicative + billing.Customer.Phones[0].Number
	}

	return address
}

func (s *EcommerceOrderCreationStrategy) createEcommerceShippingAddressFromBilling(billing *billingDomain.Billing) *ecommerceInfra.EcommerceAddress {
	now := time.Now()

	firstName := ""
	lastName := ""

	if len(billing.Customer.Name) > 0 {
		if len(billing.Customer.Name) > 1 {
			firstName = billing.Customer.Name[0]
			lastName = strings.Join(billing.Customer.Name[1:], " ")
		} else {
			fullName := billing.Customer.Name[0]
			nameParts := strings.Fields(strings.TrimSpace(fullName))
			if len(nameParts) > 1 {
				firstName = nameParts[0]
				lastName = strings.Join(nameParts[1:], " ")
			} else {
				firstName = fullName
				lastName = ""
			}
		}
	}

	var addressInfo billingDomain.CustomerAddress
	if billing.Customer.ShippingAddress != nil {
		addressInfo = *billing.Customer.ShippingAddress
		fmt.Printf("[EcommerceOrderCreation] Using customer shipping address: %+v\n", addressInfo)
	} else {
		addressInfo = billing.Customer.Address
		fmt.Printf("[EcommerceOrderCreation] Using customer billing address as fallback for shipping: %+v\n", addressInfo)
	}

	address := &ecommerceInfra.EcommerceAddress{
		FirstName:     firstName,
		LastName:      lastName,
		Email:         billing.Customer.Email,
		City:          addressInfo.City.CityName,
		Address1:      addressInfo.Address,
		ZipPostalCode: addressInfo.PostalCode,
		Country:       addressInfo.City.CountryName,
		Province:      addressInfo.City.StateName,
		CreatedOnUTC:  now,
		CountryID:     49,
	}

	if len(billing.Customer.Phones) > 0 {
		address.PhoneNumber = billing.Customer.Phones[0].Indicative + billing.Customer.Phones[0].Number
	}

	return address
}

func (s *EcommerceOrderCreationStrategy) createEcommerceShoppingCartItemFromOrders(orders []*orderDomain.Order, customerID int, productID int) *ecommerceInfra.EcommerceShoppingCartItem {
	now := time.Now()

	cartItem := &ecommerceInfra.EcommerceShoppingCartItem{
		Quantity:         1,
		CreatedOnUTC:     now,
		ShoppingCartType: "ShoppingCart",
		ProductID:        productID,
		CustomerID:       customerID,
	}

	return cartItem
}

func (s *EcommerceOrderCreationStrategy) createEcommerceOrderFromOrders(orders []*orderDomain.Order, customerID int, item *itemDomain.Item, billingAddressID, shippingAddressID int) *ecommerceInfra.EcommerceSimpleOrder {
	now := time.Now()
	totalAmount := float64(0)

	for _, order := range orders {
		itemAmount := float64(order.OfferedAmount)
		totalAmount += itemAmount
	}

	order := &ecommerceInfra.EcommerceSimpleOrder{
		StoreID:                 1,
		PaymentMethodSystemName: "Payments.CashOnDelivery",
		CustomerCurrencyCode:    "COP",
		CurrencyRate:            1,
		OrderTax:                0,
		OrderTotal:              totalAmount,
		PaidDateUTC:             now,
		CreatedOnUTC:            now,
		CustomerID:              customerID,
		BillingAddress:          &ecommerceInfra.EcommerceSimpleAddress{ID: billingAddressID},
		ShippingAddress:         &ecommerceInfra.EcommerceSimpleAddress{ID: shippingAddressID},
	}

	return order
}
