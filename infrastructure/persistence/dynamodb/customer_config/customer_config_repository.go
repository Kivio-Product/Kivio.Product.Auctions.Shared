package infrastructure

import (
	"context"
	"fmt"
	"log"
	"os"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/customer_config"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

type CustomerConfigRepository interface {
	GetByCustomerID(ctx context.Context, customerID, pointOfSaleID string) (*domain.CustomerConfig, error)
	Save(ctx context.Context, config *domain.CustomerConfig) error
	Update(ctx context.Context, config *domain.CustomerConfig) error
	Delete(ctx context.Context, customerID, pointOfSaleID string) error
	GetByPointOfSaleID(ctx context.Context, pointOfSaleID string) ([]domain.CustomerConfig, error)
}

type customerConfigRepository struct {
	client    *dynamodb.DynamoDB
	tableName string
}

func NewCustomerConfigRepository() CustomerConfigRepository {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-2"),
	})
	if err != nil {
		log.Fatal(err)
	}

	tableName := os.Getenv("DYNAMODB_CUSTOMER_CONFIG_TABLE")
	if tableName == "" {
		tableName = "customer_configurations"
	}

	return &customerConfigRepository{
		client:    dynamodb.New(sess),
		tableName: tableName,
	}
}

func (r *customerConfigRepository) GetByCustomerID(ctx context.Context, customerID, pointOfSaleID string) (*domain.CustomerConfig, error) {
	input := &dynamodb.GetItemInput{
		TableName: aws.String(r.tableName),
		Key: map[string]*dynamodb.AttributeValue{
			"customer_id": {
				S: aws.String(customerID),
			},
			"point_of_sale_id": {
				S: aws.String(pointOfSaleID),
			},
		},
	}

	result, err := r.client.GetItemWithContext(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to get customer config from DynamoDB: %w", err)
	}

	if result.Item == nil {
		return nil, fmt.Errorf("customer config not found")
	}

	var config domain.CustomerConfig
	err = dynamodbattribute.UnmarshalMap(result.Item, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal customer config: %w", err)
	}

	return &config, nil
}

func (r *customerConfigRepository) Save(ctx context.Context, config *domain.CustomerConfig) error {
	item, err := dynamodbattribute.MarshalMap(config)
	if err != nil {
		return fmt.Errorf("failed to marshal customer config: %w", err)
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(r.tableName),
		Item:      item,
	}

	_, err = r.client.PutItemWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to save customer config to DynamoDB: %w", err)
	}

	return nil
}

func (r *customerConfigRepository) Update(ctx context.Context, config *domain.CustomerConfig) error {
	return r.Save(ctx, config)
}

func (r *customerConfigRepository) Delete(ctx context.Context, customerID, pointOfSaleID string) error {
	input := &dynamodb.DeleteItemInput{
		TableName: aws.String(r.tableName),
		Key: map[string]*dynamodb.AttributeValue{
			"customer_id": {
				S: aws.String(customerID),
			},
			"point_of_sale_id": {
				S: aws.String(pointOfSaleID),
			},
		},
	}

	_, err := r.client.DeleteItemWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to delete customer config from DynamoDB: %w", err)
	}

	return nil
}

func (r *customerConfigRepository) GetByPointOfSaleID(ctx context.Context, pointOfSaleID string) ([]domain.CustomerConfig, error) {
	input := &dynamodb.QueryInput{
		TableName:              aws.String(r.tableName),
		IndexName:              aws.String("GSI1-PointOfSaleIndex"),
		KeyConditionExpression: aws.String("point_of_sale_id = :pos_id"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":pos_id": {
				S: aws.String(pointOfSaleID),
			},
		},
	}

	result, err := r.client.QueryWithContext(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to query customer configs by point of sale ID: %w", err)
	}

	var configs []domain.CustomerConfig
	for _, item := range result.Items {
		var config domain.CustomerConfig
		err := dynamodbattribute.UnmarshalMap(item, &config)
		if err != nil {
			log.Printf("Failed to unmarshal customer config: %v", err)
			continue
		}
		configs = append(configs, config)
	}

	return configs, nil
}