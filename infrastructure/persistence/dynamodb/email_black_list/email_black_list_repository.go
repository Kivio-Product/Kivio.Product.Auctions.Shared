package infrastructure

import (
	"context"
	"fmt"
	"log"
	"os"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/email_black_list"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

type EmailBlackListRepository interface {
	Save(ctx context.Context, emailBlackList *domain.EmailBlackList) error
	GetBlackListEmails() (map[string]struct{}, error)
}

type emailBlackListRepository struct {
	client         *dynamodb.DynamoDB
	blackListTable string
}

func NewEmailBlackListRepository() EmailBlackListRepository {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-2")})
	if err != nil {
		log.Fatal(err)
	}

	blackListTable := os.Getenv("DYNAMODB_EMAIL_BLACK_LIST_TABLE")
	if blackListTable == "" {
		blackListTable = "EmailBlackList"
	}

	return &emailBlackListRepository{
		client:         dynamodb.New(sess),
		blackListTable: blackListTable,
	}
}

func (r *emailBlackListRepository) Save(ctx context.Context, i *domain.EmailBlackList) error {
	item, err := dynamodbattribute.MarshalMap(i)
	if err != nil {
		return fmt.Errorf("failed to map order")
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(r.blackListTable),
		Item:      item,
	}

	_, err = r.client.PutItemWithContext(ctx, input)

	if err != nil {
		return fmt.Errorf("failed to put item in DynamoDB")
	}

	return nil
}

func (r *emailBlackListRepository) GetBlackListEmails() (map[string]struct{}, error) {
	result, err := r.client.Scan(&dynamodb.ScanInput{
		TableName: aws.String(r.blackListTable),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to scan table %s: %w", r.blackListTable, err)
	}
	var items []domain.EmailBlackList
	if err := dynamodbattribute.UnmarshalListOfMaps(result.Items, &items); err != nil {
		return nil, err
	}

	emailSet := make(map[string]struct{})
	for _, item := range items {
		if item.Email != "" {
			emailSet[item.Email] = struct{}{}
		}
	}

	return emailSet, nil
}
