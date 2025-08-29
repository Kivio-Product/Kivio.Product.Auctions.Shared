package infrastructure

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

type ItemRepository interface {
	SaveItem(ctx context.Context, item *domain.Item) error
	GetAllItems() ([]domain.Item, error)
	GetItemById(ctx context.Context, itemId string) (*domain.Item, error)
	DeleteItem(ctx context.Context, itemId string) error
	GetItemsByPosId(id string, filters map[string]string) ([]domain.Item, error)
	GetItemsByUserID(userID string) ([]domain.Item, error)
	BatchGetItemsByIds(ctx context.Context, itemIds []string) ([]domain.Item, error)
	GetItemsByPosIdPaged(ctx context.Context, posID string, limit int, lastEvaluatedKey map[string]*dynamodb.AttributeValue) ([]domain.Item, map[string]*dynamodb.AttributeValue, error)
}

type itemRepository struct {
	client     *dynamodb.DynamoDB
	itemTable  string
	orderTable string
}

func NewItemRepository() ItemRepository {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-2")})
	if err != nil {
		log.Fatal(err)
	}

	itemTable := os.Getenv("DYNAMODB_ITEMS_TABLE")
	if itemTable == "" {
		itemTable = "Item"
	}

	orderTable := os.Getenv("DYNAMODB_ORDERS_TABLE")
	if orderTable == "" {
		orderTable = "Order"
	}

	return &itemRepository{
		client:     dynamodb.New(sess),
		itemTable:  itemTable,
		orderTable: orderTable,
	}
}

func (r *itemRepository) SaveItem(ctx context.Context, i *domain.Item) error {
	item, err := dynamodbattribute.MarshalMap(i)
	if err != nil {
		return fmt.Errorf("failed to map item")
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(r.itemTable),
		Item:      item,
	}

	_, err = r.client.PutItemWithContext(ctx, input)

	if err != nil {
		fmt.Print(err)
		return fmt.Errorf("failed to put item in DynamoDB")
	}

	return nil
}

func (r *itemRepository) GetAllItems() ([]domain.Item, error) {
	result, err := r.client.Scan(&dynamodb.ScanInput{
		TableName: aws.String(r.itemTable),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to scan table %s", r.itemTable)
	}
	var items []domain.Item

	for _, item := range result.Items {
		var fitems domain.Item
		err := dynamodbattribute.UnmarshalMap(item, &fitems)
		if err != nil {
			log.Printf("Failed to get table items")
			continue
		}
		items = append(items, fitems)
	}

	return items, nil
}

func (r *itemRepository) GetItemById(ctx context.Context, itemId string) (*domain.Item, error) {
	result, err := r.client.GetItem(&dynamodb.GetItemInput{
		TableName: aws.String(r.itemTable),
		Key: map[string]*dynamodb.AttributeValue{
			"ItemId": {
				S: aws.String(itemId),
			},
		},
	})

	if err != nil {
		return nil, fmt.Errorf("failed to get item with ID %s", itemId)
	}

	if result.Item == nil {
		return nil, fmt.Errorf("item with ID %s not found", itemId)
	}

	var item domain.Item
	err = dynamodbattribute.UnmarshalMap(result.Item, &item)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal item with ID %s", itemId)
	}

	return &item, nil
}

func (r *itemRepository) GetItemsByPosId(posId string, filters map[string]string) ([]domain.Item, error) {
	exprAttrNames := map[string]*string{}
	exprAttrValues := map[string]*dynamodb.AttributeValue{}
	var filterExpr []string

	exprAttrValues[":posId"] = &dynamodb.AttributeValue{S: aws.String(posId)}

	if name, ok := filters["name"]; ok && name != "" {
		exprAttrNames["#name"] = aws.String("Name")
		exprAttrValues[":nameValue"] = &dynamodb.AttributeValue{S: aws.String(name)}
		filterExpr = append(filterExpr, "contains(#name, :nameValue)")
	}

	input := &dynamodb.QueryInput{
		TableName:              aws.String(r.itemTable),
		IndexName:              aws.String("PointOfSaleId-index"),
		KeyConditionExpression: aws.String("PointOfSaleId = :posId"),
	}

	if len(exprAttrNames) > 0 {
		input.ExpressionAttributeNames = exprAttrNames
	}
	if len(exprAttrValues) > 0 {
		input.ExpressionAttributeValues = exprAttrValues
	}
	if len(filterExpr) > 0 {
		input.FilterExpression = aws.String(strings.Join(filterExpr, " AND "))
	}

	result, err := r.client.Query(input)
	if err != nil {
		return nil, fmt.Errorf("failed to query items for PosId %s: %w", posId, err)
	}

	var items []domain.Item
	err = dynamodbattribute.UnmarshalListOfMaps(result.Items, &items)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal items: %w", err)
	}

	return items, nil
}

func (r *itemRepository) GetItemsByUserID(userID string) ([]domain.Item, error) {

	input := &dynamodb.QueryInput{
		TableName:              aws.String("PointOfSale"),
		IndexName:              aws.String("UserId-index"),
		KeyConditionExpression: aws.String("UserId = :userId"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":userId": {S: aws.String(userID)},
		},
	}

	result, err := r.client.Query(input)
	if err != nil {
		return nil, err
	}

	var pointOfSaleIDs []string
	for _, item := range result.Items {
		var pos struct {
			ID string `json:"PointOfSaleId"`
		}
		err = dynamodbattribute.UnmarshalMap(item, &pos)
		if err != nil {
			return nil, err
		}
		pointOfSaleIDs = append(pointOfSaleIDs, pos.ID)
	}

	if len(pointOfSaleIDs) == 0 {
		return nil, nil
	}

	var items []domain.Item
	for _, posID := range pointOfSaleIDs {
		input := &dynamodb.QueryInput{
			TableName:              aws.String("Item"),
			IndexName:              aws.String("PointOfSaleId-index"),
			KeyConditionExpression: aws.String("PointOfSaleId = :posID"),
			ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
				":posID": {S: aws.String(posID)},
			},
		}

		result, err := r.client.Query(input)
		if err != nil {
			return nil, err
		}

		for _, item := range result.Items {
			var it domain.Item
			err = dynamodbattribute.UnmarshalMap(item, &it)
			if err != nil {
				return nil, err
			}
			items = append(items, it)
		}
	}

	return items, nil
}

func (r *itemRepository) DeleteItem(ctx context.Context, itemId string) error {
	_, err := r.client.DeleteItemWithContext(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(r.itemTable),
		Key: map[string]*dynamodb.AttributeValue{
			"ItemId": {
				S: aws.String(itemId),
			},
		},
	})

	if err != nil {
		return fmt.Errorf("failed to delete item from DynamoDB")
	}

	return nil
}

func (r *itemRepository) BatchGetItemsByIds(ctx context.Context, itemIds []string) ([]domain.Item, error) {
	if len(itemIds) == 0 {
		return nil, nil
	}
	keys := make([]map[string]*dynamodb.AttributeValue, len(itemIds))
	for i, id := range itemIds {
		keys[i] = map[string]*dynamodb.AttributeValue{
			"ItemId": {S: aws.String(id)},
		}
	}
	input := &dynamodb.BatchGetItemInput{
		RequestItems: map[string]*dynamodb.KeysAndAttributes{
			r.itemTable: {
				Keys: keys,
			},
		},
	}
	result, err := r.client.BatchGetItemWithContext(ctx, input)
	if err != nil {
		return nil, err
	}
	items := result.Responses[r.itemTable]
	var domainItems []domain.Item
	for _, item := range items {
		var domainItem domain.Item
		if err := dynamodbattribute.UnmarshalMap(item, &domainItem); err != nil {
			continue
		}
		domainItems = append(domainItems, domainItem)
	}
	return domainItems, nil
}

func (r *itemRepository) GetItemsByPosIdPaged(ctx context.Context, posID string, limit int, lastEvaluatedKey map[string]*dynamodb.AttributeValue) ([]domain.Item, map[string]*dynamodb.AttributeValue, error) {
	input := &dynamodb.QueryInput{
		TableName:              aws.String(r.itemTable),
		IndexName:              aws.String("PointOfSaleId-index"),
		KeyConditionExpression: aws.String("PointOfSaleId = :posId"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":posId": {S: aws.String(posID)},
		},
		Limit:             aws.Int64(int64(limit)),
		ExclusiveStartKey: lastEvaluatedKey,
	}

	result, err := r.client.QueryWithContext(ctx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("error al consultar items por PosId: %w", err)
	}

	var items []domain.Item
	if err := dynamodbattribute.UnmarshalListOfMaps(result.Items, &items); err != nil {
		return nil, nil, fmt.Errorf("error al deserializar items: %w", err)
	}

	return items, result.LastEvaluatedKey, nil
}
