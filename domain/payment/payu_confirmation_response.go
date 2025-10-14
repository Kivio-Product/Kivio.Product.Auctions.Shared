package payment

type ConfirmationResponse struct {
	MerchantId    string
	ReferenceSale string
	TransactionId string
	Sign          string
	Value         float64
	ValueStr      string
	Currency      string
	StatePol      int
	PaymentMethod string
	Extra1        string
}
