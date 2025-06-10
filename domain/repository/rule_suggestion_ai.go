package domain

import (
	sheetsDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/sheets"
)

type RuleSuggestionAI interface {
	SuggestRulesSheets(sheetData sheetsDomain.SheetData) ([]sheetsDomain.RuleField, error)
	SuggestRulesEcommerce(ecommerceResponse []byte) ([]sheetsDomain.RuleField, error)
}
