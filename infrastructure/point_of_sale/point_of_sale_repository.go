package infrastructure

import (
	"context"
	"fmt"
	"log"
	"os"

	pointofsale "github.com/Kivio-Product/Kivio.Product.Auctions.Offers/internal/domain/pointOfSale"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

type PosRepository struct {
	client           *dynamodb.DynamoDB
	pointOfSaleTable string
	userByPosTable   string
}

type IPosRepository interface {
	SavePointOfSale(ctx context.Context, pointOfSale *pointofsale.PointOfSale) error
	GetAllPos() ([]pointofsale.PointOfSale, error)
	GetUserPos(id string) ([]pointofsale.PointOfSale, error)
	GetPosUser(id string) ([]pointofsale.UserByPos, error)
	GetPosById(ctx context.Context, posId string) (*pointofsale.PointOfSale, error)
	DeletePos(ctx context.Context, posId string) error
}

func NewPosRepository() IPosRepository {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-2")})
	if err != nil {
		log.Fatal(err)
	}

	pointOfSaleTable := os.Getenv("DYNAMODB_POINT_OF_SALE_TABLE")
	if pointOfSaleTable == "" {
		pointOfSaleTable = "PointOfSale"
	}

	userByPosTable := os.Getenv("DYNAMODB_USER_BY_POS_TABLE")
	if userByPosTable == "" {
		userByPosTable = "UserByPos"
	}

	return &PosRepository{
		client:           dynamodb.New(sess),
		pointOfSaleTable: pointOfSaleTable,
		userByPosTable:   userByPosTable,
	}
}

func (r *PosRepository) GetAllPos() ([]pointofsale.PointOfSale, error) {
	result, err := r.client.Scan(&dynamodb.ScanInput{
		TableName: aws.String(r.pointOfSaleTable),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to scan table %s: %w", r.pointOfSaleTable, err)
	}
	var pos []pointofsale.PointOfSale

	for _, item := range result.Items {
		var fitems pointofsale.PointOfSale
		err := dynamodbattribute.UnmarshalMap(item, &fitems)
		if err != nil {
			log.Printf("failed to get table items: %v", err)
			continue
		}
		pos = append(pos, fitems)
	}

	return pos, nil
}

func (r *PosRepository) GetPosById(ctx context.Context, posId string) (*pointofsale.PointOfSale, error) {
	result, err := r.client.GetItemWithContext(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(r.pointOfSaleTable),
		Key: map[string]*dynamodb.AttributeValue{
			"PointOfSaleId": {
				S: aws.String(posId),
			},
		},
	})

	if err != nil {
		return nil, fmt.Errorf("failed to get pos with ID %s: %w", posId, err)
	}

	if result.Item == nil {
		return nil, fmt.Errorf("pos with ID %s not found", posId)
	}

	var item pointofsale.PointOfSale
	err = dynamodbattribute.UnmarshalMap(result.Item, &item)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal pos with ID %s: %w", posId, err)
	}

	return &item, nil
}

func (r *PosRepository) GetUserPos(userId string) ([]pointofsale.PointOfSale, error) {
	result, err := r.client.Scan(&dynamodb.ScanInput{
		TableName: aws.String(r.pointOfSaleTable),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to scan table %s: %w", r.pointOfSaleTable, err)
	}
	var pos []pointofsale.PointOfSale

	for _, item := range result.Items {
		var fitems pointofsale.PointOfSale
		err := dynamodbattribute.UnmarshalMap(item, &fitems)
		if err != nil {
			log.Printf("Failed to get table items: %v", err)
			continue
		}
		if fitems.UserId == userId {
			pos = append(pos, fitems)
		}
	}

	return pos, nil
}

func (r *PosRepository) GetPosUser(posId string) ([]pointofsale.UserByPos, error) {
	result, err := r.client.Scan(&dynamodb.ScanInput{
		TableName: aws.String(r.userByPosTable),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to scan table %s: %w", r.userByPosTable, err)
	}
	var user []pointofsale.UserByPos

	for _, item := range result.Items {
		var fitems pointofsale.UserByPos
		err := dynamodbattribute.UnmarshalMap(item, &fitems)
		if err != nil {
			log.Printf("Failed to get table items: %v", err)
			continue
		}
		if fitems.PosId == posId {
			user = append(user, fitems)
		}
	}

	return user, nil
}

func (r *PosRepository) SavePointOfSale(ctx context.Context, pointOfSale *pointofsale.PointOfSale) error {
	item, err := dynamodbattribute.MarshalMap(pointOfSale)
	if err != nil {
		return fmt.Errorf("failed to map point of sale: %w", err)
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(r.pointOfSaleTable),
		Item:      item,
	}

	_, err = r.client.PutItemWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to put item in DynamoDB: %w", err)
	}

	return nil
}

func (r *PosRepository) DeletePos(ctx context.Context, posId string) error {
	_, err := r.client.DeleteItemWithContext(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(r.pointOfSaleTable),
		Key: map[string]*dynamodb.AttributeValue{
			"PointOfSaleId": {
				S: aws.String(posId),
			},
		},
	})

	return err
}
