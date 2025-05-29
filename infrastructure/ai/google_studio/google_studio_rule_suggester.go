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

func (s *GoogleStudioRuleSuggester) SuggestRules(sheetData sheetsDomain.SheetData) (map[string][]sheetsDomain.RuleField, error) {
	if len(sheetData.Values) < 2 {
		return nil, fmt.Errorf("insufficient data in sheet")
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

	categorizedRules := make(map[string][]sheetsDomain.RuleField)
	var localRules []sheetsDomain.RuleField
	var otherRules []sheetsDomain.RuleField

	for _, rule := range suggestedRules {
		switch strings.ToLower(rule.Field) {
		case "date", "fecha", "fecha de última entrada", "fecha de última salida", "fecha de vencimiento":
			localRules = append(localRules, rule)
		case "availability", "disponibilidad", "stock actual", "stock mínimo", "stock máximo":
			localRules = append(localRules, rule)
		default:
			otherRules = append(otherRules, rule)
		}
	}

	categorizedRules["local"] = localRules
	if len(otherRules) > 0 {
		categorizedRules["google sheets"] = otherRules
	}

	return categorizedRules, nil
}
