package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/repository"
	sheetsDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/sheets"
	s3Infra "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/s3"
)

type RuleSuggestionCache interface {
	GetCachedSuggestionsSheets(ctx context.Context, pointOfSaleId string, headers []interface{}) ([]sheetsDomain.RuleField, error)
	GetCachedSuggestionsEcommerce(ctx context.Context, pointOfSaleId string) ([]sheetsDomain.RuleField, error)
	CacheSuggestionsSheets(ctx context.Context, pointOfSaleId string, headers []interface{}, suggestions []sheetsDomain.RuleField) error
	CacheSuggestionsEcommerce(ctx context.Context, pointOfSaleId string, suggestions []sheetsDomain.RuleField) error
}

type ruleSuggestionCache struct {
	fileStorage   *s3Infra.S3FileStorage
	fileReader    *s3Infra.S3FileReader
	ruleSuggester domain.RuleSuggestionAI
}

func NewRuleSuggestionCache(
	fileStorage *s3Infra.S3FileStorage,
	fileReader *s3Infra.S3FileReader,
	ruleSuggester domain.RuleSuggestionAI,
) RuleSuggestionCache {
	return &ruleSuggestionCache{
		fileStorage:   fileStorage,
		fileReader:    fileReader,
		ruleSuggester: ruleSuggester,
	}
}

type cachedSuggestion struct {
	Headers     []interface{}            `json:"headers,omitempty"`
	Suggestions []sheetsDomain.RuleField `json:"suggestions"`
	LastUpdated time.Time                `json:"lastUpdated"`
}

func (c *ruleSuggestionCache) GetCachedSuggestionsSheets(ctx context.Context, pointOfSaleId string, headers []interface{}) ([]sheetsDomain.RuleField, error) {
	key := fmt.Sprintf("rule-suggestions-sheets/%s.json", pointOfSaleId)

	reader, err := c.fileReader.GetFileContent(key)
	if err != nil {
		return nil, fmt.Errorf("error getting cached sheet suggestions: %w", err)
	}
	defer reader.Close()

	var cached cachedSuggestion
	if err := json.NewDecoder(reader).Decode(&cached); err != nil {
		return nil, fmt.Errorf("error decoding cached sheet suggestions: %w", err)
	}

	if !areHeadersEqual(cached.Headers, headers) {
		return nil, fmt.Errorf("headers have changed, need to regenerate suggestions")
	}

	return cached.Suggestions, nil
}

func (c *ruleSuggestionCache) GetCachedSuggestionsEcommerce(ctx context.Context, pointOfSaleId string) ([]sheetsDomain.RuleField, error) {
	key := fmt.Sprintf("rule-suggestions-ecommerce/%s.json", pointOfSaleId)

	reader, err := c.fileReader.GetFileContent(key)
	if err != nil {
		return nil, fmt.Errorf("error getting cached ecommerce suggestions: %w", err)
	}
	defer reader.Close()

	var cached cachedSuggestion
	if err := json.NewDecoder(reader).Decode(&cached); err != nil {
		return nil, fmt.Errorf("error decoding cached ecommerce suggestions: %w", err)
	}

	return cached.Suggestions, nil
}

func (c *ruleSuggestionCache) CacheSuggestionsSheets(ctx context.Context, pointOfSaleId string, headers []interface{}, suggestions []sheetsDomain.RuleField) error {
	key := fmt.Sprintf("rule-suggestions-sheets/%s.json", pointOfSaleId)

	cached := cachedSuggestion{
		Headers:     headers,
		Suggestions: suggestions,
		LastUpdated: time.Now(),
	}

	data, err := json.Marshal(cached)
	if err != nil {
		return fmt.Errorf("error marshaling sheet suggestions: %w", err)
	}

	if err := c.fileStorage.Upload(ctx, key, bytes.NewReader(data)); err != nil {
		return fmt.Errorf("error caching sheet suggestions: %w", err)
	}

	return nil
}

func (c *ruleSuggestionCache) CacheSuggestionsEcommerce(ctx context.Context, pointOfSaleId string, suggestions []sheetsDomain.RuleField) error {
	key := fmt.Sprintf("rule-suggestions-ecommerce/%s.json", pointOfSaleId)

	cached := cachedSuggestion{
		Suggestions: suggestions,
		LastUpdated: time.Now(),
	}

	data, err := json.Marshal(cached)
	if err != nil {
		return fmt.Errorf("error marshaling ecommerce suggestions: %w", err)
	}

	if err := c.fileStorage.Upload(ctx, key, bytes.NewReader(data)); err != nil {
		return fmt.Errorf("error caching ecommerce suggestions: %w", err)
	}

	return nil
}

func areHeadersEqual(headers1, headers2 []interface{}) bool {
	if len(headers1) != len(headers2) {
		return false
	}

	for i := range headers1 {
		if headers1[i] != headers2[i] {
			return false
		}
	}

	return true
}
