package infrastructure

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/billing"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

type BillingRepository interface {
	SaveBilling(ctx context.Context, billing *domain.Billing) error
	GetBillingByID(ctx context.Context, billingID string) (*domain.Billing, error)
	GetAllBillings(ctx context.Context) ([]domain.Billing, error)
	UpdateBilling(ctx context.Context, billing *domain.Billing) error
	GetOrderBillingPaginated(ctx context.Context, params orderDomain.PaginationParams, filters map[string]string) (*domain.BillingRepositoryResult, error)
}

type billingRepository struct {
	client       *dynamodb.DynamoDB
	billingTable string
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

	return &billingRepository{
		client:       dynamodb.New(sess),
		billingTable: billingTable,
	}
}

func (r *billingRepository) SaveBilling(ctx context.Context, i *domain.Billing) error {
	item, err := dynamodbattribute.MarshalMap(i)
	if err != nil {
		return fmt.Errorf("failed to map order")
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(r.billingTable),
		Item:      item,
	}

	_, err = r.client.PutItemWithContext(ctx, input)

	if err != nil {
		return fmt.Errorf("failed to put item in DynamoDB")
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

	return nil
}

func (r *billingRepository) GetOrderBillingPaginated(ctx context.Context, params orderDomain.PaginationParams, filters map[string]string) (*domain.BillingRepositoryResult, error) {
	exprAttrNames := map[string]*string{}
	exprAttrValues := map[string]*dynamodb.AttributeValue{}
	var filterExpr []string

	exprAttrValues[":posIdValue"] = &dynamodb.AttributeValue{S: aws.String(params.PointOfSaleId)}
	keyCondition := "posId = :posIdValue"

	if state, ok := filters["state"]; ok && state != "" {
		exprAttrNames["#state"] = aws.String("state")
		exprAttrValues[":stateValue"] = &dynamodb.AttributeValue{S: aws.String(state)}
		filterExpr = append(filterExpr, "#state = :stateValue")
	}

	if name, ok := filters["name"]; ok && name != "" {
		exprAttrNames["#customerId"] = aws.String("customerId")
		exprAttrValues[":customerIdValue"] = &dynamodb.AttributeValue{S: aws.String(name)}
		filterExpr = append(filterExpr, "contains(#customerId, :customerIdValue)")
	}

	if start, ok := filters["created_at_start"]; ok && start != "" {
		if end, okEnd := filters["created_at_end"]; okEnd && end != "" {
			exprAttrValues[":startDate"] = &dynamodb.AttributeValue{S: aws.String(start)}
			exprAttrValues[":endDate"] = &dynamodb.AttributeValue{S: aws.String(end)}
			keyCondition += " AND createdAt BETWEEN :startDate AND :endDate"
		} else {
			startOfDay := start[:10] + "T00:00:00Z"
			endOfDay := start[:10] + "T23:59:59Z"

			exprAttrValues[":startDate"] = &dynamodb.AttributeValue{S: aws.String(startOfDay)}
			exprAttrValues[":endDate"] = &dynamodb.AttributeValue{S: aws.String(endOfDay)}
			keyCondition += " AND createdAt BETWEEN :startDate AND :endDate"
		}
	} else if end, ok := filters["created_at_end"]; ok && end != "" {
		startOfDay := end[:10] + "T00:00:00Z"
		endOfDay := end[:10] + "T23:59:59Z"

		exprAttrValues[":startDate"] = &dynamodb.AttributeValue{S: aws.String(startOfDay)}
		exprAttrValues[":endDate"] = &dynamodb.AttributeValue{S: aws.String(endOfDay)}
		keyCondition += " AND createdAt BETWEEN :startDate AND :endDate"
	}

	baseInput := &dynamodb.QueryInput{
		TableName:              aws.String(r.billingTable),
		IndexName:              aws.String("posId-createdAt-index"),
		KeyConditionExpression: aws.String(keyCondition),
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

	var collected []domain.Billing
	currentLastKey := params.NextToken
	for {
		input := *baseInput
		input.ExclusiveStartKey = currentLastKey
		input.Limit = aws.Int64(int64(params.PageSize) + 10)

		result, err := r.client.Query(&input)
		if err != nil {
			return nil, fmt.Errorf("failed to query billings for PosId %s: %w", params.PointOfSaleId, err)
		}

		if len(result.Items) > 0 {
			var billings []domain.Billing
			err = dynamodbattribute.UnmarshalListOfMaps(result.Items, &billings)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal billings: %w", err)
			}
			collected = append(collected, billings...)
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
			"id":        {S: aws.String(lastReturnedItem.Id)},
			"posId":     {S: aws.String(lastReturnedItem.PointOfSaleId)},
			"createdAt": {S: aws.String(lastReturnedItem.CreatedAt.Format(time.RFC3339))},
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
		return nil, fmt.Errorf("failed to count billings: %w", err)
	}

	return &domain.BillingRepositoryResult{
			Billings:   collected,
			NextToken:  finalLastKey,
			TotalCount: *countResult.Count,
		},
		nil
}
