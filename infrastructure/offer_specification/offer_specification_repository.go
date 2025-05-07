package infrastructure

import (
	"context"
	"fmt"
	"log"
	"os"

	offer "github.com/Kivio-Product/Kivio.Product.Auctions.Domain.Shared/offer"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

type OfferSpecificationRepository struct {
	client             *dynamodb.DynamoDB
	specificationTable string
}

type IOfferSpecificationRepository interface {
	SaveOfferSpecification(ctx context.Context, spec *offer.OfferSpecification) error
}

func NewOfferSpecificationRepository() IOfferSpecificationRepository {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-2")})
	if err != nil {
		log.Fatal(err)
	}

	specificationTable := os.Getenv("DYNAMODB_OFFER_SPECIFICATION_TABLE")
	if specificationTable == "" {
		specificationTable = "OfferSpecification"
	}

	return &OfferSpecificationRepository{
		client:             dynamodb.New(sess),
		specificationTable: specificationTable,
	}
}

func (r *OfferSpecificationRepository) SaveOfferSpecification(ctx context.Context, spec *offer.OfferSpecification) error {
	item, err := dynamodbattribute.MarshalMap(spec)
	if err != nil {
		return fmt.Errorf("failed to map offer specification: %w", err)
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
