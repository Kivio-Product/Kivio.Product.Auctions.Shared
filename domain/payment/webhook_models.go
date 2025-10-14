package payment

type WompiWebhook struct {
	Event string `json:"event"`
	Data  struct {
		Transaction struct {
			ID            string `json:"id"`
			AmountInCents int64  `json:"amount_in_cents"`
			Reference     string `json:"reference"`
			CustomerEmail string `json:"customer_email"`
			Currency      string `json:"currency"`
			PaymentMethod string `json:"payment_method_type"`
			RedirectURL   string `json:"redirect_url"`
			Status        string `json:"status"`
		} `json:"transaction"`
	} `json:"data"`
	Environment string `json:"environment"`
	Signature   struct {
		Properties []string `json:"properties"`
		Checksum   string   `json:"checksum"`
	} `json:"signature"`
	Timestamp int64  `json:"timestamp"`
	SentAt    string `json:"sent_at"`
}
