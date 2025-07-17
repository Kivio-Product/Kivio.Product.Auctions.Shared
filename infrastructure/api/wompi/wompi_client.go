package wompi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/payment"
)

type WompiClient struct {
	BaseURL   string
	PublicKey string
}

func NewWompiClient() *WompiClient {
	return &WompiClient{
		BaseURL:   os.Getenv("WOMPI_API_URL"),
		PublicKey: os.Getenv("WOMPI_PUBLIC_KEY"),
	}
}

func (c *WompiClient) GetAcceptanceToken() (string, error) {
	url := fmt.Sprintf("%s/merchants/%s", c.BaseURL, c.PublicKey)
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result domain.WompiMerchantResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.Data.PresignedAcceptance.AcceptanceToken, nil
}
