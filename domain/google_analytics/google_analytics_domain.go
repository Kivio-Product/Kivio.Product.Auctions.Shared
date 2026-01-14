package domain

type GAEvent struct {
	Name   string                 `json:"name"`
	Params map[string]interface{} `json:"params,omitempty"`
}

type GAPayload struct {
	UserID   string    `json:"user_id,omitempty"`
	ClientID string    `json:"client_id"`
	Events   []GAEvent `json:"events"`
}

type GAItem struct {
	ItemID   string `json:"item_id"`
	ItemName string `json:"item_name"`
	Quantity int    `json:"quantity"`
	Price    int64  `json:"price"`
}
