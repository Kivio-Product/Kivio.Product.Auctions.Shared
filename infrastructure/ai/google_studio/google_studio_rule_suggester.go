package google_studio

import (
	"encoding/json"
	"fmt"
	"strings"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/repository"
	sheetsDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/sheets"
	"github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/api/google_studio"
)

type GoogleStudioRuleSuggester struct {
	client *google_studio.GoogleStudioClient
}

func NewGoogleStudioRuleSuggester() domain.RuleSuggestionAI {
	return &GoogleStudioRuleSuggester{
		client: google_studio.NewGoogleStudioClient(),
	}
}

func (s *GoogleStudioRuleSuggester) SuggestRulesSheets(sheetData sheetsDomain.SheetData) ([]sheetsDomain.RuleField, error) {
	if len(sheetData.Values) < 2 {
		return nil, fmt.Errorf("insufficient sheet data")
	}

	headers := sheetData.Values[0]
	sampleData := sheetData.Values[1:]

	prompt := fmt.Sprintf(`Based on the following spreadsheet data, suggest rules that could be used for business logic. 
For each column, determine if it would make sense to create rules for it and what type of rules would be appropriate.
Consider only columns that could be used for meaningful business rules (e.g., stock levels, prices, dates, etc.).
Ignore columns that are not suitable for rules (e.g., IDs, names, etc.).

Headers: %v
Sample Data: %v

For each suitable column, provide a response in this JSON format:
{
    "field": "column name",
    "parameterType": "one of: numérico, moneda, porcentaje, fecha, booleano, texto, categoría",
    "operators": ["=", "!=", ">", "<", ">=", "<=", "contiene", "no contiene", "está en", "no está en"]
}

Only include fields that make sense for business rules.`, headers, sampleData)

	response, err := s.client.GenerateContent(prompt)
	if err != nil {
		return nil, fmt.Errorf("error getting AI suggestions: %w", err)
	}

	cleanedResponse := strings.TrimSpace(response)
	cleanedResponse = strings.TrimPrefix(cleanedResponse, "```json")
	cleanedResponse = strings.TrimPrefix(cleanedResponse, "```")
	cleanedResponse = strings.TrimSuffix(cleanedResponse, "```")
	cleanedResponse = strings.TrimSpace(cleanedResponse)

	var suggestedRules []sheetsDomain.RuleField
	if err := json.Unmarshal([]byte(cleanedResponse), &suggestedRules); err != nil {
		return nil, fmt.Errorf("error parsing AI response: %w", err)
	}

	return suggestedRules, nil
}

func (s *GoogleStudioRuleSuggester) SuggestRulesEcommerce(ecommerceResponse []byte) ([]sheetsDomain.RuleField, error) {
	type Product struct {
		ID                  int      `json:"id"`
		Name                string   `json:"name"`
		ShortDescription    string   `json:"short_description"`
		FullDescription     string   `json:"full_description"`
		SKU                 string   `json:"sku"`
		Price               float64  `json:"price"`
		OldPrice            float64  `json:"old_price"`
		StockQuantity       int      `json:"stock_quantity"`
		Published           bool     `json:"published"`
		VisibleIndividually bool     `json:"visible_individually"`
		AvailableStartDate  string   `json:"available_start_date_time_utc"`
		AvailableEndDate    string   `json:"available_end_date_time_utc"`
		Tags                []string `json:"tags"`
		IsFreeShipping      bool     `json:"is_free_shipping"`
		Weight              float64  `json:"weight"`
		Dimensions          struct {
			Length float64 `json:"length"`
			Width  float64 `json:"width"`
			Height float64 `json:"height"`
		}
	}

	type ApiResponse struct {
		Products []Product `json:"products"`
	}

	var apiResponse ApiResponse
	if err := json.Unmarshal(ecommerceResponse, &apiResponse); err != nil {
		return nil, fmt.Errorf("error unmarshaling ecommerce response: %w", err)
	}

	sampleItems := apiResponse.Products
	if len(sampleItems) > 5 {
		sampleItems = sampleItems[:5]
	}

	prompt := fmt.Sprintf(`Based on the following ecommerce product data, suggest business rules that could be used for inventory management and pricing.
Focus ONLY on fields that can change over time and are meaningful for business decisions. DO NOT include static fields like names, IDs, or descriptions.

Consider these specific use cases:

1. Inventory Rules:
   - Stock quantity thresholds (e.g., alert when stock is low)
   - Stock availability status
   - Minimum/maximum order quantities

2. Pricing Rules:
   - Current price thresholds
   - Discount percentage (based on old_price vs price)
   - Special price conditions

3. Availability Rules:
   - Product visibility status
   - Available date ranges
   - Publication status

4. Category Rules:
   - Product tags for categorization
   - Shipping conditions

Sample Products: %+v

For each suitable field, provide a response in this JSON format:
{
    "field": "field name",
    "parameterType": "one of: numérico, moneda, porcentaje, fecha, booleano, categoría",
    "operators": ["=", "!=", ">", "<", ">=", "<=", "está en", "no está en"]
}

IMPORTANT RULES:
1. DO NOT include static fields like name, ID, or descriptions
2. DO NOT include redundant fields
3. DO NOT combine fields in a single rule
4. Only include fields that can change over time and affect business decisions
5. Focus on fields that can be used to trigger actions or alerts

Example of good rules:
- Stock quantity below threshold
- Price above/below certain value
- Product available within date range
- Product has specific tag
- Product is published/visible

Example of bad rules (DO NOT INCLUDE):
- Name equals something (static)
- ID equals something (static)
- Description contains something (static)
- Combining multiple fields in one rule`, sampleItems)

	response, err := s.client.GenerateContent(prompt)
	if err != nil {
		return nil, fmt.Errorf("error getting AI suggestions: %w", err)
	}

	cleanedResponse := strings.TrimSpace(response)
	cleanedResponse = strings.TrimPrefix(cleanedResponse, "```json")
	cleanedResponse = strings.TrimPrefix(cleanedResponse, "```")
	cleanedResponse = strings.TrimSuffix(cleanedResponse, "```")
	cleanedResponse = strings.TrimSpace(cleanedResponse)

	var suggestedRules []sheetsDomain.RuleField
	if err := json.Unmarshal([]byte(cleanedResponse), &suggestedRules); err != nil {
		return nil, fmt.Errorf("error parsing AI response: %w", err)
	}

	return suggestedRules, nil
}
