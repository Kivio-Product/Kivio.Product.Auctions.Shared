package infrastructure

import (
	"context"
	"fmt"
	"log"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item_specification"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

type ItemSpecificationRepository interface {
	Save(ctx context.Context, itemSpecification *domain.ItemSpecification) error
	Get() ([]domain.ItemSpecification, error)
	GetById(ctx context.Context, itemId string) (*domain.ItemSpecification, error)
	Delete(ctx context.Context, id string) error
	GetItemSpecByOffer(id string) ([]domain.ItemSpecification, error)
	GetItemSpecByItem(id string) ([]domain.ItemSpecification, error)
	UpdateItemSpec(ctx context.Context, itemSpec *domain.ItemSpecification) error
}

type itemSpecificationRepository struct {
	client                 *dynamodb.DynamoDB
	itemSpecificationTable string
}

var (
	itemSpecificationTable = "ItemSpecification"
)

func NewItemSpecificationRepository() ItemSpecificationRepository {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-2")})
	if err != nil {
		log.Fatal(err)
	}

	return &itemSpecificationRepository{
		client:                 dynamodb.New(sess),
		itemSpecificationTable: itemSpecificationTable,
	}
}

func (r *itemSpecificationRepository) Save(ctx context.Context, i *domain.ItemSpecification) error {
	itemSpecification, err := dynamodbattribute.MarshalMap(i)
	if err != nil {
		return fmt.Errorf("failed to map item")
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(r.itemSpecificationTable),
		Item:      itemSpecification,
	}

	_, err = r.client.PutItemWithContext(ctx, input)

	if err != nil {
		return fmt.Errorf("failed to put item in DynamoDB")
	}

	return nil
}

func (r *itemSpecificationRepository) Get() ([]domain.ItemSpecification, error) {
	result, err := r.client.Scan(&dynamodb.ScanInput{
		TableName: aws.String(r.itemSpecificationTable),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to scan table %s", r.itemSpecificationTable)
	}
	var items []domain.ItemSpecification

	for _, item := range result.Items {
		var fitems domain.ItemSpecification
		err := dynamodbattribute.UnmarshalMap(item, &fitems)
		if err != nil {
			log.Printf("Failed to get table items")
			continue
		}
		items = append(items, fitems)
	}

	return items, nil
}

func (r *itemSpecificationRepository) GetById(ctx context.Context, itemId string) (*domain.ItemSpecification, error) {
	item, err := r.client.GetItem(&dynamodb.GetItemInput{
		TableName: aws.String(r.itemSpecificationTable),
		Key: map[string]*dynamodb.AttributeValue{
			"Id": {
				S: aws.String(itemId),
			},
		},
	})

	if err != nil {
		return nil, fmt.Errorf("failed to get item with ID %s", itemId)
	}

	if item.Item == nil {
		return nil, fmt.Errorf("item with ID %s not found", itemId)
	}

	var itemSpec domain.ItemSpecification
	err = dynamodbattribute.UnmarshalMap(item.Item, &itemSpec)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal item with ID %s", itemId)
	}

	return &itemSpec, nil
}

func (r *itemSpecificationRepository) Delete(ctx context.Context, id string) error {
	_, err := r.client.DeleteItemWithContext(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(r.itemSpecificationTable),
		Key: map[string]*dynamodb.AttributeValue{
			"Id": {
				S: aws.String(id),
			},
		},
	})

	if err != nil {
		return fmt.Errorf("failed to delete item specification from DynamoDB")
	}

	return nil
}

func (r *itemSpecificationRepository) GetItemSpecByOffer(offerId string) ([]domain.ItemSpecification, error) {
	result, err := r.client.Scan(&dynamodb.ScanInput{
		TableName: aws.String(r.itemSpecificationTable),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to scan table %s", r.itemSpecificationTable)
	}

	var items []domain.ItemSpecification

	for _, item := range result.Items {
		var fitems domain.ItemSpecification
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

func (r *itemSpecificationRepository) GetItemSpecByItem(itemId string) ([]domain.ItemSpecification, error) {
	result, err := r.client.Scan(&dynamodb.ScanInput{
		TableName: aws.String(r.itemSpecificationTable),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to scan table %s", r.itemSpecificationTable)
	}

	var items []domain.ItemSpecification

	for _, item := range result.Items {
		var fitems domain.ItemSpecification
		err := dynamodbattribute.UnmarshalMap(item, &fitems)
		if err != nil {
			log.Printf("Failed to get table items")
			continue
		}
		if fitems.ItemId == itemId {
			items = append(items, fitems)
		}
	}

	return items, nil
}

func (r *itemSpecificationRepository) UpdateItemSpec(ctx context.Context, itemSpec *domain.ItemSpecification) error {
	result, err := dynamodbattribute.MarshalMap(itemSpec)
	if err != nil {
		return fmt.Errorf("failed to marshal item Specification: %w", err)
	}

	_, err = r.client.PutItem(&dynamodb.PutItemInput{
		TableName: aws.String(r.itemSpecificationTable),
		Item:      result,
	})
	if err != nil {
		return fmt.Errorf("failed to update item Specification: %w", err)
	}

	return nil
}
