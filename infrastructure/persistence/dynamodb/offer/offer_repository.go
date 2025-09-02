package infrastructure

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

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
	GetPosOffersFiltered(posId string, filters map[string]string, limit int, lastKey map[string]*dynamodb.AttributeValue) ([]domain.Offer, map[string]*dynamodb.AttributeValue, int64, error)
	GetPosOffers(posId string, limit int, lastKey map[string]*dynamodb.AttributeValue) ([]domain.Offer, map[string]*dynamodb.AttributeValue, error)
	GetOfferById(ctx context.Context, offerId string) (*domain.Offer, error)
	DeleteOffer(ctx context.Context, offerId string) error
	BatchGetOffersByIds(ctx context.Context, offerIds []string) ([]domain.Offer, error)
	CountOffers(ctx context.Context) (int64, error)
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

func (r *OfferRepository) GetPosOffersFiltered(
	posId string,
	filters map[string]string,
	limit int,
	lastKey map[string]*dynamodb.AttributeValue,
) ([]domain.Offer, map[string]*dynamodb.AttributeValue, int64, error) {

	exprAttrNames := map[string]*string{}
	exprAttrValues := map[string]*dynamodb.AttributeValue{}
	var filterExpr []string

	exprAttrValues[":posIdValue"] = &dynamodb.AttributeValue{S: aws.String(posId)}
	keyCondition := "PosId = :posIdValue"

	if state, ok := filters["state"]; ok && state != "" {
		exprAttrNames["#state"] = aws.String("State")
		exprAttrValues[":stateValue"] = &dynamodb.AttributeValue{S: aws.String(state)}
		filterExpr = append(filterExpr, "#state = :stateValue")
	}

	if typ, ok := filters["type"]; ok && typ != "" {
		exprAttrNames["#type"] = aws.String("Type")
		exprAttrValues[":typeValue"] = &dynamodb.AttributeValue{S: aws.String(typ)}
		filterExpr = append(filterExpr, "#type = :typeValue")
	}

	if name, ok := filters["name"]; ok && name != "" {
		exprAttrNames["#name"] = aws.String("Name")
		exprAttrValues[":nameValue"] = &dynamodb.AttributeValue{S: aws.String(name)}
		filterExpr = append(filterExpr, "contains(#name, :nameValue)")
	}

	if start, ok := filters["created_at_start"]; ok && start != "" {
		if end, okEnd := filters["created_at_end"]; okEnd && end != "" {
			exprAttrValues[":startDate"] = &dynamodb.AttributeValue{S: aws.String(start)}
			exprAttrValues[":endDate"] = &dynamodb.AttributeValue{S: aws.String(end)}
			keyCondition += " AND CreatedAt BETWEEN :startDate AND :endDate"
		} else {
			startOfDay := start[:10] + "T00:00:00Z"
			endOfDay := start[:10] + "T23:59:59Z"

			exprAttrValues[":startDate"] = &dynamodb.AttributeValue{S: aws.String(startOfDay)}
			exprAttrValues[":endDate"] = &dynamodb.AttributeValue{S: aws.String(endOfDay)}
			keyCondition += " AND CreatedAt BETWEEN :startDate AND :endDate"
		}
	} else if end, ok := filters["created_at_end"]; ok && end != "" {
		startOfDay := end[:10] + "T00:00:00Z"
		endOfDay := end[:10] + "T23:59:59Z"

		exprAttrValues[":startDate"] = &dynamodb.AttributeValue{S: aws.String(startOfDay)}
		exprAttrValues[":endDate"] = &dynamodb.AttributeValue{S: aws.String(endOfDay)}
		keyCondition += " AND CreatedAt BETWEEN :startDate AND :endDate"
	}

	baseInput := &dynamodb.QueryInput{
		TableName:              aws.String(r.offerTable),
		IndexName:              aws.String("PosId-CreatedAt-index"),
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

	var collected []domain.Offer
	currentLastKey := lastKey
	for {
		input := *baseInput
		input.ExclusiveStartKey = currentLastKey
		input.Limit = aws.Int64(int64(limit) + 10)

		result, err := r.client.Query(&input)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("failed to query offers for PosId %s: %w", posId, err)
		}

		if len(result.Items) > 0 {
			var offers []domain.Offer
			err = dynamodbattribute.UnmarshalListOfMaps(result.Items, &offers)
			if err != nil {
				return nil, nil, 0, fmt.Errorf("failed to unmarshal offers: %w", err)
			}
			collected = append(collected, offers...)
		}

		currentLastKey = result.LastEvaluatedKey
		if len(collected) >= limit || currentLastKey == nil {
			break
		}
	}

	var finalLastKey map[string]*dynamodb.AttributeValue
	if len(collected) > limit {
		lastReturnedItem := collected[limit-1]
		finalLastKey = map[string]*dynamodb.AttributeValue{
			"OfferId":   {S: aws.String(lastReturnedItem.OfferId)},
			"PosId":     {S: aws.String(lastReturnedItem.PosId)},
			"CreatedAt": {S: aws.String(lastReturnedItem.CreatedAt.Format(time.RFC3339))},
		}
		collected = collected[:limit]
	} else {
		finalLastKey = currentLastKey
	}

	countInput := *baseInput
	countInput.Limit = nil
	countInput.ExclusiveStartKey = nil
	countInput.Select = aws.String("COUNT")

	countResult, err := r.client.Query(&countInput)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to count offers: %w", err)
	}

	return collected, finalLastKey, *countResult.Count, nil
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

func (r *OfferRepository) BatchGetOffersByIds(ctx context.Context, offerIds []string) ([]domain.Offer, error) {
	if len(offerIds) == 0 {
		return nil, nil
	}
	keys := make([]map[string]*dynamodb.AttributeValue, len(offerIds))
	for i, id := range offerIds {
		keys[i] = map[string]*dynamodb.AttributeValue{
			"OfferId": {S: aws.String(id)},
		}
	}
	input := &dynamodb.BatchGetItemInput{
		RequestItems: map[string]*dynamodb.KeysAndAttributes{
			r.offerTable: {
				Keys: keys,
			},
		},
	}
	result, err := r.client.BatchGetItemWithContext(ctx, input)
	if err != nil {
		return nil, err
	}
	items := result.Responses[r.offerTable]
	var offers []domain.Offer
	for _, item := range items {
		var offer domain.Offer
		if err := dynamodbattribute.UnmarshalMap(item, &offer); err != nil {
			continue
		}
		offers = append(offers, offer)
	}
	return offers, nil
}

func (r *OfferRepository) CountOffers(ctx context.Context) (int64, error) {
	input := &dynamodb.ScanInput{
		TableName: aws.String(r.offerTable),
		Select:    aws.String("COUNT"),
	}
	result, err := r.client.ScanWithContext(ctx, input)
	if err != nil {
		return 0, err
	}
	return *result.Count, nil
}
