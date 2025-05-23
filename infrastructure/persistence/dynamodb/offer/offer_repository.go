package infrastructure

import (
	"context"
	"fmt"
	"log"
	"os"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/offer"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

type OfferRepository struct {
	client     *dynamodb.DynamoDB
	offerTable string
}

type IOfferRepository interface {
	SaveOffer(ctx context.Context, offer *domain.Offer) error
	GetAllOffers() ([]domain.Offer, error)
	GetPosOffers(posId string, limit int, lastKey map[string]*dynamodb.AttributeValue) ([]domain.Offer, map[string]*dynamodb.AttributeValue, error)
	GetOfferById(ctx context.Context, offerId string) (*domain.Offer, error)
	DeleteOffer(ctx context.Context, offerId string) error
}

func NewOfferRepository() IOfferRepository {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-2")})
	if err != nil {
		log.Fatal(err)
	}

	offerTable := os.Getenv("DYNAMODB_OFFERS_TABLE")
	if offerTable == "" {
		offerTable = "Offers"
	}

	return &OfferRepository{
		client:     dynamodb.New(sess),
		offerTable: offerTable,
	}
}

func (r *OfferRepository) SaveOffer(ctx context.Context, offer *domain.Offer) error {
	item, err := dynamodbattribute.MarshalMap(offer)
	if err != nil {
		return fmt.Errorf("failed to map offer: %w", err)
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(r.offerTable),
		Item:      item,
	}

	_, err = r.client.PutItemWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to put item in DynamoDB: %w", err)
	}

	return nil
}

func (r *OfferRepository) DeleteOffer(ctx context.Context, offerId string) error {
	_, err := r.client.DeleteItemWithContext(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(r.offerTable),
		Key: map[string]*dynamodb.AttributeValue{
			"OfferId": {
				S: aws.String(offerId),
			},
		},
	})

	return err
}

func (r *OfferRepository) GetAllOffers() ([]domain.Offer, error) {
	result, err := r.client.Scan(&dynamodb.ScanInput{
		TableName: aws.String(r.offerTable),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to scan table %s: %w", r.offerTable, err)
	}
	var offers []domain.Offer

	for _, item := range result.Items {
		var offer domain.Offer
		err := dynamodbattribute.UnmarshalMap(item, &offer)
		if err != nil {
			log.Printf("failed to get table items: %v", err)
			continue
		}
		offers = append(offers, offer)
	}

	return offers, nil
}

func (r *OfferRepository) GetPosOffers(posId string, limit int, lastKey map[string]*dynamodb.AttributeValue) ([]domain.Offer, map[string]*dynamodb.AttributeValue, error) {
	input := &dynamodb.QueryInput{
		TableName:              aws.String(r.offerTable),
		IndexName:              aws.String("PosId-CreatedAt-index"),
		ExclusiveStartKey:      lastKey,
		ScanIndexForward:       aws.Bool(false),
		KeyConditionExpression: aws.String("PosId = :posIdValue"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":posIdValue": {
				S: aws.String(posId),
			},
		},
	}

	if limit > 0 {
		input.Limit = aws.Int64(int64(limit))
	}

	result, err := r.client.Query(input)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to query offers for PosId %s: %w", posId, err)
	}

	var offers []domain.Offer
	if len(result.Items) > 0 {
		err = dynamodbattribute.UnmarshalListOfMaps(result.Items, &offers)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal offers: %w", err)
		}
	}

	return offers, result.LastEvaluatedKey, nil
}

func (r *OfferRepository) GetOfferById(ctx context.Context, offerId string) (*domain.Offer, error) {
	result, err := r.client.GetItemWithContext(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(r.offerTable),
		Key: map[string]*dynamodb.AttributeValue{
			"OfferId": {
				S: aws.String(offerId),
			},
		},
	})

	if err != nil {
		return nil, fmt.Errorf("failed to get offer with ID %s: %w", offerId, err)
	}

	if result.Item == nil {
		return nil, fmt.Errorf("offer with ID %s not found", offerId)
	}

	var item domain.Offer
	err = dynamodbattribute.UnmarshalMap(result.Item, &item)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal offer with ID %s: %w", offerId, err)
	}
	return &item, nil
}
