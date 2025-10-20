package domain

import (
	"fmt"
	"strings"
	"time"
)

// ExtractColumnValues extracts all values from a specific column in a 2D array
// 
// This utility function processes a 2D array (typically from spreadsheet data)
// and extracts all values from a specified column index. It safely handles
// rows that may not have the specified column and converts all values
// to strings for consistent processing.
//
// Parameters:
//   - rows: 2D array containing data rows
//   - col: Column index to extract values from
//
// Returns:
//   - []string: Array of string values from the specified column
//
// Side Effects:
//   - None (pure function)
//
// Technical Details:
//   - Safely handles rows with insufficient columns
//   - Converts all values to strings using fmt.Sprintf
//   - Returns empty slice if no valid data found
//   - Column index is zero-based
//   - Handles nil values gracefully
func ExtractColumnValues(rows [][]interface{}, col int) []string {
	var values []string
	for _, row := range rows {
		if col < len(row) {
			values = append(values, fmt.Sprintf("%v", row[col]))
		}
	}
	return values
}

// InferType analyzes a collection of string values and infers the most appropriate data type
// 
// This function performs intelligent type inference on a collection of string values
// by analyzing patterns, formats, and content characteristics. It uses heuristics
// to determine whether the data represents numbers, dates, currencies, percentages,
// booleans, categories, or plain text.
//
// Parameters:
//   - values: Array of string values to analyze
//
// Returns:
//   - string: Inferred data type (e.g., "numérico", "fecha", "moneda", "porcentaje", "booleano", "categoría", "texto")
//
// Side Effects:
//   - None (pure function)
//
// Technical Details:
//   - Uses multiple type detection algorithms
//   - Prioritizes specialized types (percentage, currency, date, boolean)
//   - Uses category detection for small unique value sets
//   - Handles Spanish boolean values ("activo", "inactivo")
//   - Returns "texto" as fallback for unrecognized patterns
//   - Case-insensitive analysis
func InferType(values []string) string {
	numeric, text, boolean, date, currency, percentage := 0, 0, 0, 0, 0, 0
	unique := map[string]bool{}

	for _, v := range values {
		str := strings.ToLower(strings.TrimSpace(v))
		unique[str] = true

		if str == "" {
			continue
		} else if isNumber(str) {
			numeric++
		} else if isCurrency(str) {
			currency++
		} else if isPercentage(str) {
			percentage++
		} else if isDate(str) {
			date++
		} else if str == "true" || str == "false" || str == "activo" || str == "inactivo" {
			boolean++
		} else {
			text++
		}
	}

	if len(unique) < 10 && text >= numeric {
		return "categoría"
	} else if percentage > 0 {
		return "porcentaje"
	} else if currency > 0 {
		return "moneda"
	} else if date > 0 {
		return "fecha"
	} else if boolean > 0 {
		return "booleano"
	} else if numeric > 0 {
		return "numérico"
	}
	return "texto"
}

// isNumber checks if a string represents a valid numeric value
// 
// This helper function determines whether a string can be parsed as a valid
// floating-point number. It uses Go's fmt.Sscanf to attempt parsing and
// returns true if successful.
//
// Parameters:
//   - s: String to check for numeric format
//
// Returns:
//   - bool: True if string represents a valid number, false otherwise
//
// Side Effects:
//   - None (pure function)
//
// Technical Details:
//   - Uses fmt.Sscanf with "%f" format for float64 parsing
//   - Handles integers, decimals, and scientific notation
//   - Returns false for empty strings or invalid formats
//   - Case-sensitive (no case conversion performed)
func isNumber(s string) bool {
	_, err := fmt.Sscanf(s, "%f", new(float64))
	return err == nil
}

// isCurrency checks if a string represents a currency value
// 
// This helper function determines whether a string contains currency
// indicators, specifically looking for Colombian Peso (COP) references
// or dollar sign symbols.
//
// Parameters:
//   - s: String to check for currency indicators
//
// Returns:
//   - bool: True if string contains currency indicators, false otherwise
//
// Side Effects:
//   - None (pure function)
//
// Technical Details:
//   - Looks for "cop" substring (case-sensitive)
//   - Looks for "$" symbol
//   - Returns true if either indicator is found
//   - Does not validate currency amount format
//   - Case-sensitive search
func isCurrency(s string) bool {
	return strings.Contains(s, "cop") || strings.Contains(s, "$")
}

// isPercentage checks if a string represents a percentage value
// 
// This helper function determines whether a string ends with a percentage
// symbol, indicating it represents a percentage value.
//
// Parameters:
//   - s: String to check for percentage format
//
// Returns:
//   - bool: True if string ends with "%", false otherwise
//
// Side Effects:
//   - None (pure function)
//
// Technical Details:
//   - Uses strings.HasSuffix to check for "%" at end
//   - Does not validate numeric portion before "%"
//   - Case-sensitive check
//   - Returns false for empty strings
func isPercentage(s string) bool {
	return strings.HasSuffix(s, "%")
}

// isDate checks if a string represents a valid date in common formats
// 
// This helper function determines whether a string can be parsed as a valid
// date using common date formats. It supports multiple date layouts including
// ISO format, European format, and US format.
//
// Parameters:
//   - s: String to check for date format
//
// Returns:
//   - bool: True if string represents a valid date, false otherwise
//
// Side Effects:
//   - None (pure function)
//
// Technical Details:
//   - Supports formats: "2006-01-02", "02/01/2006", "01/02/2006"
//   - Uses Go's time.Parse for validation
//   - Returns true if any supported format matches
//   - Handles both European (DD/MM/YYYY) and US (MM/DD/YYYY) formats
//   - Returns false for empty strings or invalid formats
func isDate(s string) bool {
	layouts := []string{"2006-01-02", "02/01/2006", "01/02/2006"}
	for _, layout := range layouts {
		if _, err := time.Parse(layout, s); err == nil {
			return true
		}
	}
	return false
}
