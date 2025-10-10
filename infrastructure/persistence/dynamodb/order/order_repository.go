package infrastructure

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

type OrderRepository interface {
	SaveOrder(ctx context.Context, order *domain.Order) error
	GetAllOrders(ctx context.Context) ([]domain.Order, error)
	GetItemSpecificationOrder(id string) ([]domain.Order, error)
	GetOfferOrder(id string) ([]domain.Order, error)
	GetOrdersByOfferId(ctx context.Context, offerId string) ([]domain.Order, error)
	GetIdOrder(ctx context.Context, eofferId string) (*domain.Order, error)
	DeleteOrder(ctx context.Context, orderId string) error
	UpdateOrder(ctx context.Context, order *domain.Order) error
	GetOrdersBillingByID(ctx context.Context, billingID string) ([]domain.Order, error)
	GetOrdersPaginated(ctx context.Context, params domain.PaginationParams, filters map[string]string) (*domain.OrderRepositoryResult, error)
	CountOrders(ctx context.Context, pointOfSaleId string) (int64, error)
	GetOrdersByPointOfSaleId(ctx context.Context, pointOfSaleId string) ([]domain.Order, error)
}

type orderRepository struct {
	client     *dynamodb.DynamoDB
	orderTable string
}

func NewOrderRepository() OrderRepository {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-2")})
	if err != nil {
		log.Fatal(err)
	}

	orderTable := os.Getenv("DYNAMODB_ORDERS_TABLE")
	if orderTable == "" {
		orderTable = "Order"
	}

	return &orderRepository{
		client:     dynamodb.New(sess),
		orderTable: orderTable,
	}
}

func (r *orderRepository) SaveOrder(ctx context.Context, i *domain.Order) error {
	item, err := dynamodbattribute.MarshalMap(i)
	if err != nil {
		return fmt.Errorf("failed to map order")
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(r.orderTable),
		Item:      item,
	}

	_, err = r.client.PutItemWithContext(ctx, input)

	if err != nil {
		return fmt.Errorf("failed to put item in DynamoDB")
	}

	return nil
}

func (r *orderRepository) GetAllOrders(ctx context.Context) ([]domain.Order, error) {
	result, err := r.client.ScanWithContext(ctx, &dynamodb.ScanInput{
		TableName: aws.String(r.orderTable),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to scan table %s", r.orderTable)
	}
	var orders []domain.Order

	for _, item := range result.Items {
		var fitems domain.Order
		err := dynamodbattribute.UnmarshalMap(item, &fitems)
		if err != nil {
			log.Printf("Failed to get table orders")
			continue
		}
		orders = append(orders, fitems)
	}

	return orders, nil
}

func (r *orderRepository) GetItemSpecificationOrder(itemSpecificationId string) ([]domain.Order, error) {
	result, err := r.client.Scan(&dynamodb.ScanInput{
		TableName: aws.String(r.orderTable),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to scan table %s", r.orderTable)
	}

	var items []domain.Order

	for _, item := range result.Items {
		var fitems domain.Order
		err := dynamodbattribute.UnmarshalMap(item, &fitems)
		if err != nil {
			log.Printf("Failed to get table items")
			continue
		}
		if fitems.ItemSpecificationId == itemSpecificationId {
			items = append(items, fitems)
		}
	}

	return items, nil
}

func (r *orderRepository) GetOfferOrder(offerId string) ([]domain.Order, error) {
	result, err := r.client.Scan(&dynamodb.ScanInput{
		TableName: aws.String(r.orderTable),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to scan table %s", r.orderTable)
	}

	var items []domain.Order

	for _, item := range result.Items {
		var fitems domain.Order
		err := dynamodbattribute.UnmarshalMap(item, &fitems)
		if err != nil {
			log.Printf("Failed to get table items")
			continue
		}
		if fitems.OfferId == offerId {
			items = append(items, fitems)
		}
	}

	return items, nil
}

func (r *orderRepository) GetIdOrder(ctx context.Context, orderId string) (*domain.Order, error) {
	result, err := r.client.GetItem(&dynamodb.GetItemInput{
		TableName: aws.String(r.orderTable),
		Key: map[string]*dynamodb.AttributeValue{
			"OrderId": {
				S: aws.String(orderId),
			},
		},
	})

	if err != nil {
		return nil, fmt.Errorf("failed to get item with ID %s", orderId)
	}

	if result.Item == nil {
		return nil, fmt.Errorf("item with ID %s not found", orderId)
	}

	var item domain.Order
	err = dynamodbattribute.UnmarshalMap(result.Item, &item)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal item with ID %s", orderId)
	}

	return &item, nil
}

func (r *orderRepository) DeleteOrder(ctx context.Context, orderId string) error {
	_, err := r.client.DeleteItemWithContext(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(r.orderTable),
		Key: map[string]*dynamodb.AttributeValue{
			"OrderId": {
				S: aws.String(orderId),
			},
		},
	})

	if err != nil {
		return fmt.Errorf("failed to delete order from DynamoDB")
	}

	return nil
}

func (r *orderRepository) UpdateOrder(ctx context.Context, order *domain.Order) error {
	result, err := dynamodbattribute.MarshalMap(order)
	if err != nil {
		return fmt.Errorf("failed to marshal order: %w", err)
	}

	_, err = r.client.PutItem(&dynamodb.PutItemInput{
		TableName: aws.String(r.orderTable),
		Item:      result,
	})
	if err != nil {
		return fmt.Errorf("failed to update order: %w", err)
	}

	return nil
}

func (r *orderRepository) GetOrdersPaginated(
	ctx context.Context, params domain.PaginationParams, filters map[string]string) (*domain.OrderRepositoryResult, error) {
	exprAttrNames := map[string]*string{}
	exprAttrValues := map[string]*dynamodb.AttributeValue{}
	var filterExpr []string

	exprAttrValues[":pointOfSaleIdValue"] = &dynamodb.AttributeValue{S: aws.String(params.PointOfSaleId)}
	keyCondition := "PointOfSaleId = :pointOfSaleIdValue"

	if state, ok := filters["state"]; ok && state != "" {
		exprAttrNames["#state"] = aws.String("State")
		exprAttrValues[":stateValue"] = &dynamodb.AttributeValue{S: aws.String(state)}
		filterExpr = append(filterExpr, "#state = :stateValue")
	}

	if name, ok := filters["customerId"]; ok && name != "" {
		exprAttrNames["#customerId"] = aws.String("CustomerId")
		exprAttrValues[":customerIdValue"] = &dynamodb.AttributeValue{S: aws.String(name)}
		filterExpr = append(filterExpr, "contains(#customerId, :customerIdValue)")
	}

	if start, ok := filters["created_at_start"]; ok && start != "" {
		if end, okEnd := filters["created_at_end"]; okEnd && end != "" {
			endOfDay := end[:10] + "T23:59:59Z"
			exprAttrValues[":startDate"] = &dynamodb.AttributeValue{S: aws.String(start)}
			exprAttrValues[":endDate"] = &dynamodb.AttributeValue{S: aws.String(endOfDay)}
			keyCondition += " AND CreatedAt BETWEEN :startDate AND :endDate"
		} else {
			startOfDay := start[:10] + "T00:00:00Z"
			endOfDay := start[:10] + "T23:59:59Z"

			exprAttrValues[":startDate"] = &dynamodb.AttributeValue{S: aws.String(startOfDay)}
			exprAttrValues[":endDate"] = &dynamodb.AttributeValue{S: aws.String(endOfDay)}
			keyCondition += " AND CreatedAt BETWEEN :startDate AND :endDate"
		}
	} else if end, ok := filters["created_at_end"]; ok && end != "" {
		startOfDay := end[:10] + "T00:00:00Z"
		endOfDay := end[:10] + "T23:59:59Z"

		exprAttrValues[":startDate"] = &dynamodb.AttributeValue{S: aws.String(startOfDay)}
		exprAttrValues[":endDate"] = &dynamodb.AttributeValue{S: aws.String(endOfDay)}
		keyCondition += " AND CreatedAt BETWEEN :startDate AND :endDate"
	}

	baseInput := &dynamodb.QueryInput{
		TableName:              aws.String(r.orderTable),
		IndexName:              aws.String("PointOfSaleId-CreatedAt-index"),
		KeyConditionExpression: aws.String(keyCondition),
		ScanIndexForward:       aws.Bool(false),
	}

	if len(filterExpr) > 0 {
		baseInput.FilterExpression = aws.String(strings.Join(filterExpr, " AND "))
	}
	if len(exprAttrNames) > 0 {
		baseInput.ExpressionAttributeNames = exprAttrNames
	}
	if len(exprAttrValues) > 0 {
		baseInput.ExpressionAttributeValues = exprAttrValues
	}

	var collected []domain.Order
	currentLastKey := params.NextToken
	for {
		input := *baseInput
		input.ExclusiveStartKey = currentLastKey
		input.Limit = aws.Int64(int64(params.PageSize) + 10)

		result, err := r.client.Query(&input)
		if err != nil {
			return nil, fmt.Errorf("failed to query orders for PosId %s: %w", params.PointOfSaleId, err)
		}

		if len(result.Items) > 0 {
			var orders []domain.Order
			err = dynamodbattribute.UnmarshalListOfMaps(result.Items, &orders)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal orders: %w", err)
			}
			collected = append(collected, orders...)
		}

		currentLastKey = result.LastEvaluatedKey
		if len(collected) >= params.PageSize || currentLastKey == nil {
			break
		}
	}

	var finalLastKey map[string]*dynamodb.AttributeValue
	if len(collected) > params.PageSize {
		lastReturnedItem := collected[params.PageSize-1]
		finalLastKey = map[string]*dynamodb.AttributeValue{
			"OrderId":       {S: aws.String(lastReturnedItem.OrderId)},
			"PointOfSaleId": {S: aws.String(lastReturnedItem.PointOfSaleId)},
			"CreatedAt":     {S: aws.String(lastReturnedItem.CreatedAt.Format(time.RFC3339))},
		}
		collected = collected[:params.PageSize]
	} else {
		finalLastKey = currentLastKey
	}

	countInput := *baseInput
	countInput.Limit = nil
	countInput.ExclusiveStartKey = nil
	countInput.Select = aws.String("COUNT")

	countResult, err := r.client.Query(&countInput)
	if err != nil {
		return nil, fmt.Errorf("failed to count orders: %w", err)
	}

	return &domain.OrderRepositoryResult{
			Orders:     collected,
			NextToken:  finalLastKey,
			TotalCount: *countResult.Count,
		},
		nil
}

func (r *orderRepository) CountOrders(ctx context.Context, pointOfSaleId string) (int64, error) {
	input := &dynamodb.QueryInput{
		TableName:              aws.String(r.orderTable),
		IndexName:              aws.String("PointOfSaleId-index"),
		KeyConditionExpression: aws.String("PointOfSaleId = :pointOfSaleId"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":pointOfSaleId": {S: aws.String(pointOfSaleId)},
		},
		Select: aws.String("COUNT"),
	}

	result, err := r.client.QueryWithContext(ctx, input)
	if err != nil {
		return 0, fmt.Errorf("error counting orders: %w", err)
	}
	return *result.Count, nil
}

func (r *orderRepository) GetOrdersByOfferId(ctx context.Context, offerId string) ([]domain.Order, error) {
	var orders []domain.Order

	input := &dynamodb.ScanInput{
		TableName:        aws.String(r.orderTable),
		FilterExpression: aws.String("OfferId = :offerId"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":offerId": {S: aws.String(offerId)},
		},
	}

	for {
		result, err := r.client.ScanWithContext(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("error scanning orders by OfferId %s: %w", offerId, err)
		}

		var batch []domain.Order
		err = dynamodbattribute.UnmarshalListOfMaps(result.Items, &batch)
		if err != nil {
			return nil, fmt.Errorf("error unmarshalling orders: %w", err)
		}
		orders = append(orders, batch...)

		if result.LastEvaluatedKey == nil {
			break
		}
		input.ExclusiveStartKey = result.LastEvaluatedKey
	}

	return orders, nil
}

func (r *orderRepository) GetOrdersByPointOfSaleId(ctx context.Context, pointOfSaleId string) ([]domain.Order, error) {
	var orders []domain.Order

	input := &dynamodb.QueryInput{
		TableName:              aws.String(r.orderTable),
		IndexName:              aws.String("PointOfSaleId-CreatedAt-index"),
		KeyConditionExpression: aws.String("PointOfSaleId = :pointOfSaleId"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":pointOfSaleId": {S: aws.String(pointOfSaleId)},
		},
		ScanIndexForward: aws.Bool(false),
	}

	for {
		result, err := r.client.QueryWithContext(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("error querying orders by PointOfSaleId: %w", err)
		}

		var batch []domain.Order
		err = dynamodbattribute.UnmarshalListOfMaps(result.Items, &batch)
		if err != nil {
			return nil, fmt.Errorf("error unmarshalling orders: %w", err)
		}
		orders = append(orders, batch...)

		if result.LastEvaluatedKey == nil {
			break
		}
		input.ExclusiveStartKey = result.LastEvaluatedKey
	}

	return orders, nil
}

func (r *orderRepository) GetOrdersBillingByID(ctx context.Context, billingID string) ([]domain.Order, error) {
	result, err := r.client.Scan(&dynamodb.ScanInput{
		TableName:        aws.String(r.orderTable),
		FilterExpression: aws.String("BillingId = :billingId"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":billingId": {S: aws.String(billingID)},
		},
	})

	if err != nil {
		return nil, fmt.Errorf("failed to scan billing with ID %s: %w", billingID, err)
	}

	if len(result.Items) == 0 {
		return nil, fmt.Errorf("no billings found for ID %s", billingID)
	}

	var billings []domain.Order
	err = dynamodbattribute.UnmarshalListOfMaps(result.Items, &billings)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal billing list: %w", err)
	}

	return billings, nil
}
