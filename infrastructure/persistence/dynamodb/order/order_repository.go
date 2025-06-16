package infrastructure

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
)

type OrderRepository interface {
	SaveOrder(ctx context.Context, order *domain.Order) error
	GetAllOrders(ctx context.Context) ([]domain.Order, error)
	GetItemSpecificationOrder(id string) ([]domain.Order, error)
	GetOfferOrder(id string) ([]domain.Order, error)
	GetIdOrder(ctx context.Context, eofferId string) (*domain.Order, error)
	DeleteOrder(ctx context.Context, orderId string) error
	UpdateOrder(ctx context.Context, order *domain.Order) error
	GetOrdersPaginated(ctx context.Context, params domain.PaginationParams) (*domain.OrderRepositoryResult, error)
	CountOrders(ctx context.Context, pointOfSaleId string) (int64, error)
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

func (r *orderRepository) GetOrdersPaginated(ctx context.Context, params domain.PaginationParams) (*domain.OrderRepositoryResult, error) {
	var orders []domain.Order
	var lastEvaluatedKey map[string]*dynamodb.AttributeValue

	if params.NextToken != "" {
		if err := json.Unmarshal([]byte(params.NextToken), &lastEvaluatedKey); err != nil {
			return nil, fmt.Errorf("invalid pagination token: %w", err)
		}
	}

	var filterExpression *expression.Expression
	var builder expression.Builder
	if params.Search != "" {
		stateCondition := expression.Contains(expression.Name("State"), params.Search)
		customerIdCondition := expression.Contains(expression.Name("CustomerId"), params.Search)
		condition := expression.Or(stateCondition, customerIdCondition)
		builder = expression.NewBuilder().WithFilter(condition)
		expr, err := builder.Build()
		if err != nil {
			return nil, fmt.Errorf("error building filter expression: %w", err)
		}
		filterExpression = &expr
	}

	indexName := "PointOfSaleId-index"

	input := &dynamodb.QueryInput{
		TableName:              aws.String(r.orderTable),
		IndexName:              aws.String(indexName),
		Limit:                  aws.Int64(int64(params.PageSize)),
		ReturnConsumedCapacity: aws.String("TOTAL"),
		ExclusiveStartKey:      lastEvaluatedKey,
		ScanIndexForward:       aws.Bool(false),
		KeyConditionExpression: aws.String("PointOfSaleId = :pointOfSaleId"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":pointOfSaleId": {
				S: aws.String(params.PointOfSaleId),
			},
		},
	}

	if filterExpression != nil {
		input.FilterExpression = filterExpression.Filter()
		for k, v := range filterExpression.Names() {
			if input.ExpressionAttributeNames == nil {
				input.ExpressionAttributeNames = make(map[string]*string)
			}
			input.ExpressionAttributeNames[k] = v
		}

		if input.ExpressionAttributeValues == nil {
			input.ExpressionAttributeValues = make(map[string]*dynamodb.AttributeValue)
		}
		for k, v := range filterExpression.Values() {
			input.ExpressionAttributeValues[k] = v
		}
	}

	result, err := r.client.QueryWithContext(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("error querying orders table: %w", err)
	}

	if len(result.Items) > 0 {
		err = dynamodbattribute.UnmarshalListOfMaps(result.Items, &orders)
		if err != nil {
			return nil, fmt.Errorf("error deserializing orders: %w", err)
		}
	}

	var nextToken string
	if result.LastEvaluatedKey != nil {
		tokenBytes, err := json.Marshal(result.LastEvaluatedKey)
		if err != nil {
			return nil, fmt.Errorf("error serializing pagination token: %w", err)
		}
		nextToken = string(tokenBytes)
	}

	return &domain.OrderRepositoryResult{
		Orders:     orders,
		NextToken:  nextToken,
		TotalCount: 0,
	}, nil
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
