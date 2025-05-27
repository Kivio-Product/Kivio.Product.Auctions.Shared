package infrastructure

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/billing"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/google/uuid"
)

type BillingRepository interface {
	SaveBillingWithOrders(ctx context.Context, billing *domain.Billing, orderIds []string) error
	GetBillingByID(ctx context.Context, billingID string) (*domain.Billing, error)
	GetOrdersBillingByID(ctx context.Context, billingID string) ([]domain.BillingByOrder, error)
	GetAllBillings(ctx context.Context) ([]domain.Billing, error)
	UpdateBilling(ctx context.Context, billing *domain.Billing) error
	GetAllOrderBillings(ctx context.Context) ([]domain.BillingByOrder, error)
	GetOrderBillingPaginated(ctx context.Context, params orderDomain.PaginationParams) (*domain.BillingRepositoryResult, error)
}

type billingRepository struct {
	client        *dynamodb.DynamoDB
	billingTable  string
	relationTable string
}

func NewBillingRepository() BillingRepository {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-2")})
	if err != nil {
		log.Fatal(err)
	}

	billingTable := os.Getenv("DYNAMODB_BILLINGS_TABLE")
	if billingTable == "" {
		billingTable = "Billing"
	}

	relationTable := os.Getenv("DYNAMODB_BILLING_BY_ORDER_TABLE")
	if relationTable == "" {
		relationTable = "BillingByOrder"
	}

	return &billingRepository{
		client:        dynamodb.New(sess),
		billingTable:  billingTable,
		relationTable: relationTable,
	}
}

func (r *billingRepository) SaveBillingWithOrders(ctx context.Context, billing *domain.Billing, orderIds []string) error {
	itemBilling, err := dynamodbattribute.MarshalMap(billing)
	if err != nil {
		return fmt.Errorf("failed to marshal billing: %w", err)
	}

	var transactItems []*dynamodb.TransactWriteItem

	transactItems = append(transactItems, &dynamodb.TransactWriteItem{
		Put: &dynamodb.Put{
			TableName: aws.String(r.billingTable),
			Item:      itemBilling,
		},
	})

	for _, orderId := range orderIds {
		relation := domain.BillingByOrder{
			BillingId:  billing.Id,
			OrderId:    orderId,
			Id:         uuid.New().String(),
			State:      billing.State,
			CustomerId: *billing.CustomerId,
		}

		itemRelation, err := dynamodbattribute.MarshalMap(relation)
		if err != nil {
			return fmt.Errorf("failed to marshal billing-by-order: %w", err)
		}

		transactItems = append(transactItems, &dynamodb.TransactWriteItem{
			Put: &dynamodb.Put{
				TableName: aws.String(r.relationTable),
				Item:      itemRelation,
			},
		})
	}

	input := &dynamodb.TransactWriteItemsInput{
		TransactItems: transactItems,
	}

	_, err = r.client.TransactWriteItemsWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to execute transaction: %w", err)
	}

	return nil
}

func (r *billingRepository) GetBillingByID(ctx context.Context, billingID string) (*domain.Billing, error) {
	result, err := r.client.GetItem(&dynamodb.GetItemInput{
		TableName: aws.String(r.billingTable),
		Key: map[string]*dynamodb.AttributeValue{
			"id": {S: aws.String(billingID)},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get billing with ID %s: %w", billingID, err)
	}
	if result.Item == nil {
		return nil, fmt.Errorf("billing with ID %s not found", billingID)
	}

	var billing domain.Billing
	err = dynamodbattribute.UnmarshalMap(result.Item, &billing)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal billing: %w", err)
	}
	return &billing, nil
}

func (r *billingRepository) GetOrdersBillingByID(ctx context.Context, billingID string) ([]domain.BillingByOrder, error) {
	result, err := r.client.Scan(&dynamodb.ScanInput{
		TableName:        aws.String(r.relationTable),
		FilterExpression: aws.String("billingId = :billingId"),
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

	var billings []domain.BillingByOrder
	err = dynamodbattribute.UnmarshalListOfMaps(result.Items, &billings)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal billing list: %w", err)
	}

	return billings, nil
}

func (r *billingRepository) GetAllBillings(ctx context.Context) ([]domain.Billing, error) {
	out, err := r.client.Scan(&dynamodb.ScanInput{
		TableName: aws.String(r.billingTable),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to scan billing table: %w", err)
	}

	var billings []domain.Billing
	err = dynamodbattribute.UnmarshalListOfMaps(out.Items, &billings)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal billings: %w", err)
	}
	return billings, nil
}

func (r *billingRepository) GetAllOrderBillings(ctx context.Context) ([]domain.BillingByOrder, error) {
	out, err := r.client.Scan(&dynamodb.ScanInput{
		TableName: aws.String(r.relationTable),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to scan billing table: %w", err)
	}

	var billings []domain.BillingByOrder
	err = dynamodbattribute.UnmarshalListOfMaps(out.Items, &billings)

	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal billings: %w", err)
	}

	return billings, nil
}

func (r *billingRepository) UpdateBilling(ctx context.Context, billing *domain.Billing) error {
	itemBilling, err := dynamodbattribute.MarshalMap(billing)
	if err != nil {
		return fmt.Errorf("failed to marshal billing: %w", err)
	}

	_, err = r.client.PutItemWithContext(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(r.billingTable),
		Item:      itemBilling,
	})
	if err != nil {
		return fmt.Errorf("failed to update billing: %w", err)
	}

	err = r.updateBillingStateInOrders(ctx, billing.Id, billing.State)
	if err != nil {
		return fmt.Errorf("failed to update billing state in orders: %w", err)
	}

	return nil
}

func (r *billingRepository) GetOrderBillingPaginated(ctx context.Context, params orderDomain.PaginationParams) (*domain.BillingRepositoryResult, error) {
	var allOrderBillings []domain.BillingByOrder
	var lastEvaluatedKey map[string]*dynamodb.AttributeValue
	var totalScannedCount int64

	if params.NextToken != "" {
		if err := json.Unmarshal([]byte(params.NextToken), &lastEvaluatedKey); err != nil {
			return nil, fmt.Errorf("token de paginación inválido: %w", err)
		}
	}

	var filterExpression *expression.Expression
	var builder expression.Builder
	if params.Search != "" {
		stateCondition := expression.Contains(expression.Name("state"), params.Search)
		customerIdCondition := expression.Contains(expression.Name("customerId"), params.Search)
		condition := expression.Or(stateCondition, customerIdCondition)
		builder = expression.NewBuilder().WithFilter(condition)
		expr, err := builder.Build()
		if err != nil {
			return nil, fmt.Errorf("error al construir expresión de filtro: %w", err)
		}
		filterExpression = &expr
	}

	for len(allOrderBillings) < params.PageSize {
		input := &dynamodb.ScanInput{
			TableName:              aws.String(r.relationTable),
			Limit:                  aws.Int64(int64(params.PageSize)),
			ReturnConsumedCapacity: aws.String("TOTAL"),
			ExclusiveStartKey:      lastEvaluatedKey,
		}

		if filterExpression != nil {
			input.FilterExpression = filterExpression.Filter()
			input.ExpressionAttributeNames = filterExpression.Names()
			input.ExpressionAttributeValues = filterExpression.Values()
		}

		result, err := r.client.ScanWithContext(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("error al escanear tabla de órdenes: %w", err)
		}

		var batchOrders []domain.BillingByOrder
		if len(result.Items) > 0 {
			err = dynamodbattribute.UnmarshalListOfMaps(result.Items, &batchOrders)
			if err != nil {
				return nil, fmt.Errorf("error al deserializar órdenes del batch: %w", err)
			}
		}

		allOrderBillings = append(allOrderBillings, batchOrders...)

		lastEvaluatedKey = result.LastEvaluatedKey

		if result.LastEvaluatedKey == nil {
			log.Printf("DynamoDB Scan finished. Scanned %d items.", totalScannedCount+*result.ScannedCount)
			break
		}

		totalScannedCount += *result.ScannedCount

		if len(allOrderBillings) >= params.PageSize {
			break
		}
	}
	var currentPageOrders []domain.BillingByOrder
	var nextToken string

	if len(allOrderBillings) > params.PageSize {
		currentPageOrders = allOrderBillings[:params.PageSize]
		if lastEvaluatedKey != nil {
			tokenBytes, err := json.Marshal(lastEvaluatedKey)
			if err != nil {
				return nil, fmt.Errorf("error al serializar token de paginación: %w", err)
			}
			nextToken = string(tokenBytes)
		}

	} else {
		currentPageOrders = allOrderBillings
		if lastEvaluatedKey != nil {
			tokenBytes, err := json.Marshal(lastEvaluatedKey)
			if err != nil {
				return nil, fmt.Errorf("error al serializar token de paginación: %w", err)
			}
			nextToken = string(tokenBytes)
		} else {
			nextToken = ""
		}
	}

	var totalFilteredCount int64
	if params.Search != "" {
		countInput := &dynamodb.ScanInput{
			TableName: aws.String(r.relationTable),
			Select:    aws.String("COUNT"),
		}
		if filterExpression != nil {
			countInput.FilterExpression = filterExpression.Filter()
			countInput.ExpressionAttributeNames = filterExpression.Names()
			countInput.ExpressionAttributeValues = filterExpression.Values()
		}
		log.Println("Performing separate Scan with COUNT for total filtered count (can be slow/expensive)")
		countResult, err := r.client.ScanWithContext(ctx, countInput)
		if err != nil {
			log.Printf("Warning: Error getting total filtered count: %v", err)
			totalFilteredCount = 0
		} else {
			totalFilteredCount = *countResult.Count
			log.Printf("Total filtered count found: %d", totalFilteredCount)
		}
	} else {
		countInput := &dynamodb.ScanInput{
			TableName: aws.String(r.relationTable),
			Select:    aws.String("COUNT"),
		}
		countResult, err := r.client.ScanWithContext(ctx, countInput)
		if err != nil {
			return nil, fmt.Errorf("error al obtener conteo total sin filtro: %w", err)
		}
		totalFilteredCount = *countResult.Count
	}

	log.Printf("DynamoDB collected %d filtered items, returning page with %d items. Next page likely: %v", len(allOrderBillings), len(currentPageOrders), nextToken != "")

	return &domain.BillingRepositoryResult{
		Billings:   currentPageOrders,
		NextToken:  nextToken,
		TotalCount: totalFilteredCount,
	}, nil
}

func (r *billingRepository) updateBillingStateInOrders(ctx context.Context, billingID string, newState string) error {
	input := &dynamodb.QueryInput{
		TableName:              aws.String(r.relationTable),
		IndexName:              aws.String("billingId-index"),
		KeyConditionExpression: aws.String("billingId = :billingId"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":billingId": {
				S: aws.String(billingID),
			},
		},
	}

	result, err := r.client.Query(input)
	if err != nil {
		return fmt.Errorf("failed to query BillingByOrder by billingId: %w", err)
	}

	for _, item := range result.Items {
		var bbo domain.BillingByOrder
		err := dynamodbattribute.UnmarshalMap(item, &bbo)
		if err != nil {
			return fmt.Errorf("failed to unmarshal BillingByOrder: %w", err)
		}

		updateInput := &dynamodb.UpdateItemInput{
			TableName: aws.String(r.relationTable),
			Key: map[string]*dynamodb.AttributeValue{
				"id": {
					S: aws.String(bbo.Id),
				},
			},
			UpdateExpression: aws.String("SET #s = :newState"),
			ExpressionAttributeNames: map[string]*string{
				"#s": aws.String("state"),
			},
			ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
				":newState": {
					S: aws.String(newState),
				},
			},
		}

		_, err = r.client.UpdateItemWithContext(ctx, updateInput)
		if err != nil {
			return fmt.Errorf("failed to update BillingByOrder state: %w", err)
		}
	}

	return nil
}
