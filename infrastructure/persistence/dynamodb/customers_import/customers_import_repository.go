package infrastructure

import (
	"context"
	"fmt"
	"log"
	"os"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/customers_import"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

type CustomersImportRepository interface {
	SaveCustomersImport(ctx context.Context, billing *domain.CustomersImport) error
	Delete(id string) error
	GetCustomerImportByPosID(posId string) ([]domain.CustomersImport, error)
}

type customersImportRepository struct {
	client               *dynamodb.DynamoDB
	customersImportTable string
}

func NewCustomersImportRepository() CustomersImportRepository {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-2")})
	if err != nil {
		log.Fatal(err)
	}

	customersImportTable := os.Getenv("DYNAMODB_CUSTOMERS_IMPORT_TABLE")
	if customersImportTable == "" {
		customersImportTable = "CustomersImport"
	}

	return &customersImportRepository{
		client:               dynamodb.New(sess),
		customersImportTable: customersImportTable,
	}
}

func (r *customersImportRepository) SaveCustomersImport(ctx context.Context, i *domain.CustomersImport) error {
	item, err := dynamodbattribute.MarshalMap(i)
	if err != nil {
		return fmt.Errorf("failed to map order")
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(r.customersImportTable),
		Item:      item,
	}

	_, err = r.client.PutItemWithContext(ctx, input)

	if err != nil {
		return fmt.Errorf("failed to put item in DynamoDB", err)
	}

	return nil
}

func (r *customersImportRepository) Delete(id string) error {
	input := &dynamodb.DeleteItemInput{
		Key: map[string]*dynamodb.AttributeValue{
			"id": {
				S: aws.String(id),
			},
		},
		TableName: aws.String(r.customersImportTable),
	}

	_, err := r.client.DeleteItem(input)
	if err != nil {
		return fmt.Errorf("error deleting customers import from DynamoDB: %w", err)
	}

	return nil
}

func (r *customersImportRepository) GetCustomerImportByPosID(posId string) ([]domain.CustomersImport, error) {
	result, err := r.client.Scan(&dynamodb.ScanInput{
		TableName: aws.String(r.customersImportTable),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to scan table %s", r.customersImportTable)
	}

	var items []domain.CustomersImport

	for _, item := range result.Items {
		var fitems domain.CustomersImport
		err := dynamodbattribute.UnmarshalMap(item, &fitems)
		if err != nil {
			log.Printf("Failed to get table items")
			continue
		}
		if fitems.PosId == posId {
			items = append(items, fitems)
		}
	}

	return items, nil
}
