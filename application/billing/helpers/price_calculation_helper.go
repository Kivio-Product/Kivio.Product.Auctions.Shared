package helpers

import "fmt"

type PriceCalculation struct {
	UnitPriceInclTax float64
	UnitPriceExclTax float64
	PriceInclTax     float64
	PriceExclTax     float64
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

	// Calcular el tax rate basado en los precios originales del order item
	// taxRate = (priceInclTax - priceExclTax) / priceExclTax
	taxRate := (originalUnitPriceInclTax - originalUnitPriceExclTax) / originalUnitPriceExclTax

	// Calcular el precio unitario sin tax usando el tax rate
	// unitPriceExclTax = unitPriceInclTax / (1 + taxRate)
	unitPriceExclTax := unitPriceInclTax / (1 + taxRate)

	// Calcular los precios totales multiplicando por la cantidad
	priceInclTax := unitPriceInclTax * float64(quantity)
	priceExclTax := unitPriceExclTax * float64(quantity)

	return &PriceCalculation{
		UnitPriceInclTax: unitPriceInclTax,
		UnitPriceExclTax: unitPriceExclTax,
		PriceInclTax:     priceInclTax,
		PriceExclTax:     priceExclTax,
	}, nil
}
