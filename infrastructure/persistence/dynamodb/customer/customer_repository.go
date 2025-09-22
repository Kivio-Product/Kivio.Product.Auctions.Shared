package infrastructure

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/customer"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/google/uuid"
)

type customerRepository struct {
	client        *dynamodb.DynamoDB
	customerTable string
}

func NewCustomerRepository() domain.CustomerRepository {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-2")})
	if err != nil {
		log.Fatal(err)
	}

	customerTable := os.Getenv("DYNAMODB_CUSTOMER_TABLE")
	if customerTable == "" {
		customerTable = "Customer"
	}

	return &customerRepository{
		client:        dynamodb.New(sess),
		customerTable: customerTable,
	}
}

func (r *customerRepository) GetByEmail(ctx context.Context, email string) (*domain.Customer, error) {
	input := &dynamodb.QueryInput{
		TableName:              aws.String(r.customerTable),
		IndexName:              aws.String("email-index"),
		KeyConditionExpression: aws.String("email = :email"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":email": {
				S: aws.String(email),
			},
		},
	}

	result, err := r.client.QueryWithContext(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("error querying customer by email: %v", err)
	}

	if len(result.Items) == 0 {
		return nil, nil // Customer not found
	}

	var customer domain.Customer
	err = dynamodbattribute.UnmarshalMap(result.Items[0], &customer)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling customer: %v", err)
	}

	return &customer, nil
}

func (r *customerRepository) Create(ctx context.Context, customer *domain.Customer) error {
	if customer.ID == "" {
		customer.ID = uuid.New().String()
	}
	customer.CreatedAt = time.Now()
	customer.UpdatedAt = time.Now()

	item, err := dynamodbattribute.MarshalMap(customer)
	if err != nil {
		return fmt.Errorf("error marshaling customer: %v", err)
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(r.customerTable),
		Item:      item,
	}

	_, err = r.client.PutItemWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("error creating customer: %v", err)
	}

	return nil
}

func (r *customerRepository) Update(ctx context.Context, customer *domain.Customer) error {
	customer.UpdatedAt = time.Now()

	item, err := dynamodbattribute.MarshalMap(customer)
	if err != nil {
		return fmt.Errorf("error marshaling customer: %v", err)
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(r.customerTable),
		Item:      item,
	}

	_, err = r.client.PutItemWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("error updating customer: %v", err)
	}

	return nil
}
