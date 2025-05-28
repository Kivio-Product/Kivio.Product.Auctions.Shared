package domain

import (
	sheetsDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/sheets"
)

type RuleSuggestionAI interface {
	SuggestRules(sheetData sheetsDomain.SheetData) (map[string][]sheetsDomain.RuleField, error)
}
