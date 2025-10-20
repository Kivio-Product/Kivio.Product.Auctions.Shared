package domain

import (
	sheetsDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/sheets"
)

// RuleSuggestionAI defines the contract for AI-powered rule suggestion operations
// 
// This interface abstracts AI-powered rule suggestion operations, providing a clean contract
// for implementations that analyze data sources and generate business rule suggestions.
// It supports analysis of spreadsheet data and ecommerce responses to generate
// intelligent rule recommendations.
//
// Implementations should handle:
//   - Analysis of structured data (spreadsheets)
//   - Analysis of ecommerce API responses
//   - AI model integration for pattern recognition
//   - Rule field generation based on data patterns
//   - Error handling for AI service failures
//
type RuleSuggestionAI interface {
	// SuggestRulesSheets analyzes spreadsheet data and suggests business rules
	// 
	// This method processes structured spreadsheet data and uses AI algorithms
	// to identify patterns and suggest appropriate business rules. It analyzes
	// the data structure, content patterns, and relationships to generate
	// intelligent rule recommendations.
	//
	// Parameters:
	//   - sheetData: Structured data from spreadsheet containing business information
	//
	// Returns:
	//   - []RuleField: Array of suggested rule fields based on data analysis
	//   - error: Returns error if AI analysis fails
	//
	// Side Effects:
	//   - Processes sheet data through AI models
	//   - May make external API calls to AI services
	//
	// Technical Details:
	//   - Analyzes data patterns and structures
	//   - Uses machine learning for pattern recognition
	//   - Generates rule fields with appropriate data types
	//   - Should handle various spreadsheet formats
	//   - AI model should be trained on business rule patterns
	//   - Returns empty slice if no patterns detected
	SuggestRulesSheets(sheetData sheetsDomain.SheetData) ([]sheetsDomain.RuleField, error)

	// SuggestRulesEcommerce analyzes ecommerce API response data and suggests business rules
	// 
	// This method processes ecommerce API response data and uses AI algorithms
	// to identify patterns in product data, pricing, inventory, and other
	// ecommerce-specific information to generate relevant business rules.
	//
	// Parameters:
	//   - ecommerceResponse: Raw JSON response data from ecommerce API
	//
	// Returns:
	//   - []RuleField: Array of suggested rule fields based on ecommerce data analysis
	//   - error: Returns error if AI analysis fails
	//
	// Side Effects:
	//   - Processes ecommerce data through AI models
	//   - May make external API calls to AI services
	//
	// Technical Details:
	//   - Parses JSON ecommerce response data
	//   - Analyzes product, pricing, and inventory patterns
	//   - Uses specialized AI models for ecommerce data
	//   - Generates rules relevant to ecommerce operations
	//   - Should handle various ecommerce API formats
	//   - AI model should understand ecommerce business logic
	//   - Returns empty slice if no meaningful patterns detected
	SuggestRulesEcommerce(ecommerceResponse []byte) ([]sheetsDomain.RuleField, error)
}
