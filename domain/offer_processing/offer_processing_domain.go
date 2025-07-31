package domain

import "time"

type ProcessOfferRequest struct {
	OfferId string `json:"offer_id"`
}

type ProcessOfferResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	OfferId string `json:"offer_id"`
}

type OrderGroup struct {
	ItemSpecificationId string  `json:"item_specification_id"`
	Orders              []Order `json:"orders"`
}

type Order struct {
	OrderId             string `json:"order_id"`
	OfferId             string `json:"offer_id"`
	CustomerId          string `json:"customer_id"`
	ExternalId          string `json:"external_id"`
	ItemSpecificationId string `json:"item_specification_id"`
	OfferedAmount       int64  `json:"offered_amount"`
	State               string `json:"state"`
	ExtraData           string `json:"extra_data"`
}

type ItemSpecification struct {
	Id            string `json:"id"`
	OfferId       string `json:"offer_id"`
	ItemId        string `json:"item_id"`
	Availability  int    `json:"availability"`
	IsExternal    bool   `json:"is_external"`
	Currency      string `json:"currency"`
	Amount        int64  `json:"amount"`
	ExpireAt      string `json:"expire_at"`
	PointOfSaleId string `json:"point_of_sale_id"`
}

type EmailNotification struct {
	CustomerId        string `json:"customer_id"`
	OfferedAmount     int64  `json:"offered_amount"`
	Status            string `json:"status"`
	ConcatenatedNames string `json:"concatenated_names"`
	PointOfSaleId     string `json:"point_of_sale_id"`
}

type MerkkoProduct struct {
	Id            string `json:"id"`
	StockQuantity int    `json:"stock_quantity"`
}

type ProcessingResult struct {
	Winners []Order `json:"winners"`
	Losers  []Order `json:"losers"`
}

type OfferProcessingResult struct {
	OfferId         string             `json:"offer_id"`
	TotalWinners    int                `json:"total_winners"`
	TotalLosers     int                `json:"total_losers"`
	ItemSpecResults []ProcessingResult `json:"item_spec_results"`
	EmailsSent      int                `json:"emails_sent"`
	ProcessedAt     time.Time          `json:"processed_at"`
}
