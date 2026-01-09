package services

import (
	itemDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
)

type ItemWithDetails struct {
	itemDomain.Item
	Availability int     `json:"availability"`
	Price        float64 `json:"price"`
}

func NewItemWithDetails(item itemDomain.Item, availability int, price float64) *ItemWithDetails {
	return &ItemWithDetails{
		Item:         item,
		Availability: availability,
		Price:        price,
	}
}
