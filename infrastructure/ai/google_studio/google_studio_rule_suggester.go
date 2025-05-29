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

func (s *GoogleStudioRuleSuggester) SuggestRules(sheetData sheetsDomain.SheetData, ecommerceResponse []byte) (map[string][]sheetsDomain.RuleField, error) {
	categorizedRules := make(map[string][]sheetsDomain.RuleField)

	dateRule := sheetsDomain.RuleField{
		Field:         "date",
		ParameterType: "fecha",
		Operators:     []string{"=", "!=", ">", "<", ">=", "<="},
	}
	categorizedRules["local"] = []sheetsDomain.RuleField{dateRule}

	if len(sheetData.Values) >= 2 {
		headers := sheetData.Values[0]
		sampleData := sheetData.Values[1:]

		sheetRules, err := s.getSheetRules(headers, sampleData)
		if err != nil {
			return nil, fmt.Errorf("error getting sheet rules: %w", err)
		}
		if len(sheetRules) > 0 {
			categorizedRules["google sheets"] = sheetRules
		}
	}

	if len(ecommerceResponse) > 0 {
		ecommerceRules, err := s.getEcommerceRules(ecommerceResponse)
		if err != nil {
			return nil, fmt.Errorf("error getting ecommerce rules: %w", err)
		}
		if len(ecommerceRules) > 0 {
			categorizedRules["kivio_ecommerce"] = ecommerceRules
		}
	}

	return categorizedRules, nil
}

func (s *GoogleStudioRuleSuggester) getSheetRules(headers []interface{}, sampleData [][]interface{}) ([]sheetsDomain.RuleField, error) {
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

func (s *GoogleStudioRuleSuggester) getEcommerceRules(ecommerceResponse []byte) ([]sheetsDomain.RuleField, error) {
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

	prompt := fmt.Sprintf(`Based on the following ecommerce product data, suggest business rules that could be used for inventory management, pricing.

Sample Products: %+v

For each suitable field or combination of fields, provide a response in this JSON format:
{
    "field": "field name or combination (e.g., 'price', 'stock_quantity', 'available_dates')",
    "parameterType": "one of: numérico, moneda, porcentaje, fecha, booleano, texto, categoría",
    "operators": ["=", "!=", ">", "<", ">=", "<=", "contiene", "no contiene", "está en", "no está en"]
}

Focus on rules that would be valuable for:
1. Inventory control and stock management
2. Price optimization and discount strategies
3. Product visibility and availability

Only include fields that make sense for business rules and would provide value for decision making.`, sampleItems)

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
