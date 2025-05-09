package infrastructure

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"maps"

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
}

type orderRepository struct {
	client     *dynamodb.DynamoDB
	orderTable string
}

var (
	orderTable = "Order"
)

func NewOrderRepository() OrderRepository {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-2")})
	if err != nil {
		log.Fatal(err)
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
			return nil, fmt.Errorf("token de paginación inválido: %w", err)
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
			return nil, fmt.Errorf("error al construir expresión de filtro: %w", err)
		}
		filterExpression = &expr
	}

	indexName := "SortKey-CreatedAt-index"

	input := &dynamodb.QueryInput{
		TableName:              aws.String(orderTable),
		IndexName:              aws.String(indexName),
		Limit:                  aws.Int64(int64(params.PageSize)),
		ReturnConsumedCapacity: aws.String("TOTAL"),
		ExclusiveStartKey:      lastEvaluatedKey,
		ScanIndexForward:       aws.Bool(false),
		KeyConditionExpression: aws.String("SortKey = :sortKeyValue"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":sortKeyValue": {
				S: aws.String("ACTIVE"),
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
		maps.Copy(input.ExpressionAttributeValues, filterExpression.Values())
	}

	result, err := r.client.QueryWithContext(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("error al consultar tabla de órdenes: %w", err)
	}

	if len(result.Items) > 0 {
		err = dynamodbattribute.UnmarshalListOfMaps(result.Items, &orders)
		if err != nil {
			return nil, fmt.Errorf("error al deserializar órdenes: %w", err)
		}
	}

	var nextToken string
	if result.LastEvaluatedKey != nil {
		tokenBytes, err := json.Marshal(result.LastEvaluatedKey)
		if err != nil {
			return nil, fmt.Errorf("error al serializar token de paginación: %w", err)
		}
		nextToken = string(tokenBytes)
	}

	var totalCount int64
	if params.Search != "" {
		countInput := &dynamodb.QueryInput{
			TableName:              aws.String(orderTable),
			IndexName:              aws.String(indexName),
			Select:                 aws.String("COUNT"),
			KeyConditionExpression: aws.String("SortKey = :sortKeyValue"),
			ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
				":sortKeyValue": {
					S: aws.String("ACTIVE"),
				},
			},
		}

		if filterExpression != nil {
			countInput.FilterExpression = filterExpression.Filter()
			for k, v := range filterExpression.Names() {
				if countInput.ExpressionAttributeNames == nil {
					countInput.ExpressionAttributeNames = make(map[string]*string)
				}
				countInput.ExpressionAttributeNames[k] = v
			}
			maps.Copy(countInput.ExpressionAttributeValues, filterExpression.Values())
		}

		log.Println("Realizando consulta COUNT separada para obtener el total filtrado")
		countResult, err := r.client.QueryWithContext(ctx, countInput)
		if err != nil {
			log.Printf("Advertencia: Error al obtener conteo total filtrado: %v", err)
			totalCount = int64(len(orders))
		} else {
			totalCount = *countResult.Count
			log.Printf("Total de elementos filtrados encontrados: %d", totalCount)
		}
	} else {
		countInput := &dynamodb.QueryInput{
			TableName:              aws.String(orderTable),
			IndexName:              aws.String(indexName),
			Select:                 aws.String("COUNT"),
			KeyConditionExpression: aws.String("SortKey = :sortKeyValue"),
			ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
				":sortKeyValue": {
					S: aws.String("ACTIVE"),
				},
			},
		}

		countResult, err := r.client.QueryWithContext(ctx, countInput)
		if err != nil {
			return nil, fmt.Errorf("error al obtener conteo total sin filtro: %w", err)
		}
		totalCount = *countResult.Count
	}

	log.Printf("DynamoDB devolvió %d elementos ordenados por fecha (más recientes primero). Próxima página disponible: %v", len(orders), nextToken != "")

	return &domain.OrderRepositoryResult{
		Orders:     orders,
		NextToken:  nextToken,
		TotalCount: totalCount,
	}, nil
}
