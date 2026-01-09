package helpers

import (
	"fmt"
	"math"
)

type PriceCalculation struct {
	UnitPriceInclTax float64
	UnitPriceExclTax float64
	PriceInclTax     float64
	PriceExclTax     float64
}

func roundToTwoDecimals(value float64) float64 {
	return math.Round(value*100) / 100
}

func CalculateOrderItemPrices(
	unitPriceInclTax float64,
	originalUnitPriceInclTax float64,
	originalUnitPriceExclTax float64,
	quantity int,
) (*PriceCalculation, error) {
	if quantity <= 0 {
		return nil, fmt.Errorf("quantity must be greater than 0")
	}

	if originalUnitPriceExclTax <= 0 {
		return nil, fmt.Errorf("originalUnitPriceExclTax must be greater than 0")
	}

	taxRate := (originalUnitPriceInclTax - originalUnitPriceExclTax) / originalUnitPriceExclTax

	unitPriceExclTax := unitPriceInclTax / (1 + taxRate)

	priceInclTax := unitPriceInclTax * float64(quantity)
	priceExclTax := unitPriceExclTax * float64(quantity)

	return &PriceCalculation{
		UnitPriceInclTax: roundToTwoDecimals(unitPriceInclTax),
		UnitPriceExclTax: roundToTwoDecimals(unitPriceExclTax),
		PriceInclTax:     roundToTwoDecimals(priceInclTax),
		PriceExclTax:     roundToTwoDecimals(priceExclTax),
	}, nil
}
