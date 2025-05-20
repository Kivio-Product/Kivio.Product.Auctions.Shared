package infrastructure

import (
	"context"
	"fmt"
	"log"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/rule"
	ruleSpecDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/rule_specification"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

type RuleRepository interface {
	SaveRule(ctx context.Context, rule *domain.Rule) error
	DeleteRule(ctx context.Context, ruleId string) error
	GetRuleById(ctx context.Context, ruleId string) (*domain.Rule, error)
	GetOfferRules(id string) ([]domain.Rule, error)
	GetRulesSpecification(ruleId string) ([]ruleSpecDomain.RuleSpecification, error)
	GetRulesByPosIdPaged(ctx context.Context, posID string, limit int, lastEvaluatedKey map[string]*dynamodb.AttributeValue) ([]domain.Rule, map[string]*dynamodb.AttributeValue, error)
	GetAllRules() ([]domain.Rule, error)
}
type ruleRepository struct {
	client                 *dynamodb.DynamoDB
	ruleTable              string
	ruleSpecificationTable string
}

var (
	ruleTable              = "Rule"
	ruleSpecificationTable = "RuleSpecification"
)

func NewRuleRepository() RuleRepository {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-2")})
	if err != nil {
		log.Fatal(err)
	}

	return &ruleRepository{
		client:                 dynamodb.New(sess),
		ruleTable:              ruleTable,
		ruleSpecificationTable: ruleSpecificationTable,
	}
}

func (r *ruleRepository) SaveRule(ctx context.Context, rule *domain.Rule) error {
	item, err := dynamodbattribute.MarshalMap(rule)
	if err != nil {
		return fmt.Errorf("failed to map item: %w", err)
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(r.ruleTable),
		Item:      item,
	}

	_, err = r.client.PutItemWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to put item in DynamoDB: %w", err)
	}

	return nil
}

func (r *ruleRepository) DeleteRule(ctx context.Context, ruleId string) error {
	if ruleId == "" {
		return fmt.Errorf("invalid rule ID: cannot be empty")
	}

	_, err := r.GetRuleById(ctx, ruleId)
	if err != nil {
		return fmt.Errorf("cannot delete rule: %w", err)
	}

	_, err = r.client.DeleteItemWithContext(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(r.ruleTable),
		Key: map[string]*dynamodb.AttributeValue{
			"RuleId": {
				S: aws.String(ruleId),
			},
		},
	})

	return err
}

func (r *ruleRepository) GetRuleById(ctx context.Context, ruleId string) (*domain.Rule, error) {
	result, err := r.client.GetItemWithContext(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(r.ruleTable),
		Key: map[string]*dynamodb.AttributeValue{
			"RuleId": {
				S: aws.String(ruleId),
			},
		},
	})

	if err != nil {
		return nil, fmt.Errorf("failed to get rule with ID %s: %w", ruleId, err)
	}

	if result.Item == nil {
		return nil, fmt.Errorf("rule with ID %s not found", ruleId)
	}

	var item domain.Rule
	err = dynamodbattribute.UnmarshalMap(result.Item, &item)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal rule with ID %s: %w", ruleId, err)
	}

	return &item, nil
}

func (r *ruleRepository) GetRulesByPosIdPaged(ctx context.Context, posID string, limit int, lastEvaluatedKey map[string]*dynamodb.AttributeValue) ([]domain.Rule, map[string]*dynamodb.AttributeValue, error) {
	input := &dynamodb.QueryInput{
		TableName:              aws.String("Rule"),
		IndexName:              aws.String("PosId-index"),
		KeyConditionExpression: aws.String("PosId = :posId"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":posId": {S: aws.String(posID)},
		},
		Limit:             aws.Int64(int64(limit)),
		ExclusiveStartKey: lastEvaluatedKey,
	}

	result, err := r.client.Query(input)
	if err != nil {
		return nil, nil, fmt.Errorf("error al consultar reglas por PosId: %w", err)
	}

	var rules []domain.Rule
	if err := dynamodbattribute.UnmarshalListOfMaps(result.Items, &rules); err != nil {
		return nil, nil, fmt.Errorf("error al deserializar reglas: %w", err)
	}

	return rules, result.LastEvaluatedKey, nil
}

func (r *ruleRepository) GetOfferRules(offerId string) ([]domain.Rule, error) {
	input := &dynamodb.QueryInput{
		TableName:              aws.String(r.ruleTable),
		IndexName:              aws.String("OfferId-index"),
		KeyConditionExpression: aws.String("OfferId = :offerId"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":offerId": {S: aws.String(offerId)},
		},
	}

	result, err := r.client.Query(input)
	if err != nil {
		return nil, fmt.Errorf("failed to query rules for offer %s: %w", offerId, err)
	}

	var rules []domain.Rule
	err = dynamodbattribute.UnmarshalListOfMaps(result.Items, &rules)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal rules: %w", err)
	}

	return rules, nil
}

func (r *ruleRepository) GetAllRules() ([]domain.Rule, error) {
	result, err := r.client.Scan(&dynamodb.ScanInput{
		TableName: aws.String(r.ruleTable),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to scan table %s: %w", r.ruleTable, err)
	}
	var rules []domain.Rule

	for _, item := range result.Items {
		var rule domain.Rule
		err := dynamodbattribute.UnmarshalMap(item, &rule)
		if err != nil {
			log.Printf("failed to get table items: %v", err)
			continue
		}
		rules = append(rules, rule)
	}

	return rules, nil
}

func (r *ruleRepository) GetRulesSpecification(ruleId string) ([]ruleSpecDomain.RuleSpecification, error) {
	result, err := r.client.Scan(&dynamodb.ScanInput{
		TableName: aws.String(r.ruleSpecificationTable),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to scan table %s: %w", r.ruleSpecificationTable, err)
	}
	var spec []ruleSpecDomain.RuleSpecification

	for _, item := range result.Items {
		var fitems ruleSpecDomain.RuleSpecification
		err := dynamodbattribute.UnmarshalMap(item, &fitems)
		if err != nil {
			log.Printf("Failed to get table items: %v", err)
			continue
		}
		if fitems.RuleId == ruleId {
			spec = append(spec, fitems)
		}
	}

	return spec, nil
}
