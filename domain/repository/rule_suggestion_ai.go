package domain

import (
	itemDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
	sheetsDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/sheets"
)

type RuleSuggestionAI interface {
	SuggestRules(sheetData sheetsDomain.SheetData, ecommerceItems []itemDomain.Item) (map[string][]sheetsDomain.RuleField, error)
}
