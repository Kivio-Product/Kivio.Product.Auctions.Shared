package infrastructure

import (
	"context"
	"fmt"
	"log"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/rule_specification"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

type RuleSpecificationRepository interface {
	SaveRuleSpecification(ctx context.Context, rule *domain.RuleSpecification) error
	DeleteRuleSpecification(ctx context.Context, ruleSpecificationId string) error
	GetRuleSpecificationById(ctx context.Context, rulespecificationId string) (*domain.RuleSpecification, error)
	GetRuleSpecificationByOfferId(ctx context.Context, offerId string) ([]domain.RuleSpecification, error)
	GetRuleSpecificationsByRuleId(id string) ([]domain.RuleSpecification, error)
}

type ruleSpecificationRepository struct {
	client             *dynamodb.DynamoDB
	specificationTable string
}

var (
	ruleSpecificationTable = "RuleSpecification"
)

func NewRuleSpecificationRepository() RuleSpecificationRepository {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-2")})
	if err != nil {
		log.Fatal(err)
	}

	return &ruleSpecificationRepository{
		client:             dynamodb.New(sess),
		specificationTable: ruleSpecificationTable,
	}
}

func (r *ruleSpecificationRepository) SaveRuleSpecification(ctx context.Context, ruleSpec *domain.RuleSpecification) error {
	item, err := dynamodbattribute.MarshalMap(ruleSpec)
	if err != nil {
		return fmt.Errorf("failed to map item: %w", err)
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(r.specificationTable),
		Item:      item,
	}

	_, err = r.client.PutItemWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to put item in DynamoDB: %w", err)
	}

	return nil
}

func (r *ruleSpecificationRepository) DeleteRuleSpecification(ctx context.Context, ruleSpecificationId string) error {
	_, err := r.client.DeleteItemWithContext(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(r.specificationTable),
		Key: map[string]*dynamodb.AttributeValue{
			"RuleSpecificationId": {
				S: aws.String(ruleSpecificationId),
			},
		},
	})

	return err
}

func (r *ruleSpecificationRepository) GetRuleSpecificationById(ctx context.Context, ruleSpecificationId string) (*domain.RuleSpecification, error) {
	result, err := r.client.GetItemWithContext(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(r.specificationTable),
		Key: map[string]*dynamodb.AttributeValue{
			"RuleSpecificationId": {
				S: aws.String(ruleSpecificationId),
			},
		},
	})

	if err != nil {
		return nil, fmt.Errorf("failed to get ruleSpecification with ID %s: %w", ruleSpecificationId, err)
	}

	if result.Item == nil {
		return nil, fmt.Errorf("ruleSpecification with ID %s not found", ruleSpecificationId)
	}

	var item domain.RuleSpecification
	err = dynamodbattribute.UnmarshalMap(result.Item, &item)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal ruleSpecification with ID %s: %w", ruleSpecificationId, err)
	}

	return &item, nil
}

func (r *ruleSpecificationRepository) GetRuleSpecificationsByRuleId(ruleId string) ([]domain.RuleSpecification, error) {
	input := &dynamodb.QueryInput{
		TableName:              aws.String(r.specificationTable),
		IndexName:              aws.String("RuleId-index"),
		KeyConditionExpression: aws.String("RuleId = :ruleId"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":ruleId": {S: aws.String(ruleId)},
		},
	}
	result, err := r.client.Query(input)
	if err != nil {
		return nil, fmt.Errorf("failed to query rule specifications: %w", err)
	}

	var specifications []domain.RuleSpecification
	if err := dynamodbattribute.UnmarshalListOfMaps(result.Items, &specifications); err != nil {
		return nil, fmt.Errorf("failed to unmarshal rule specifications: %w", err)
	}

	return specifications, nil
}

func (r *ruleSpecificationRepository) GetRuleSpecificationByOfferId(ctx context.Context, offerId string) ([]domain.RuleSpecification, error) {
	input := &dynamodb.QueryInput{
		TableName:              aws.String(r.specificationTable),
		IndexName:              aws.String("OfferId-index"),
		KeyConditionExpression: aws.String("OfferId = :offerId"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":offerId": {S: aws.String(offerId)},
		},
	}
	result, err := r.client.Query(input)
	if err != nil {
		return nil, fmt.Errorf("failed to query rule specifications: %w", err)
	}

	var specifications []domain.RuleSpecification
	if err := dynamodbattribute.UnmarshalListOfMaps(result.Items, &specifications); err != nil {
		return nil, fmt.Errorf("failed to unmarshal rule specifications: %w", err)
	}

	return specifications, nil
}
