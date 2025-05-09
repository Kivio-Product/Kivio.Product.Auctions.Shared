package domain

import (
	"fmt"
	"strings"
	"time"
)

func ExtractColumnValues(rows [][]interface{}, col int) []string {
	var values []string
	for _, row := range rows {
		if col < len(row) {
			values = append(values, fmt.Sprintf("%v", row[col]))
		}
	}
	return values
}

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

func isNumber(s string) bool {
	_, err := fmt.Sscanf(s, "%f", new(float64))
	return err == nil
}

func isCurrency(s string) bool {
	return strings.Contains(s, "cop") || strings.Contains(s, "$")
}

func isPercentage(s string) bool {
	return strings.HasSuffix(s, "%")
}

func isDate(s string) bool {
	layouts := []string{"2006-01-02", "02/01/2006", "01/02/2006"}
	for _, layout := range layouts {
		if _, err := time.Parse(layout, s); err == nil {
			return true
		}
	}
	return false
}
