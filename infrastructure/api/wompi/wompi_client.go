package wompi

import (
	"bytes"
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

func (c *WompiClient) GetAcceptanceTokenInfo() (*domain.AcceptanceTokenInfo, error) {
	url := fmt.Sprintf("%s/merchants/%s", c.BaseURL, c.PublicKey)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result domain.WompiMerchantResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	info := &domain.AcceptanceTokenInfo{
		PresignedAcceptance:       result.Data.PresignedAcceptance,
		PresignedPersonalDataAuth: result.Data.PresignedPersonalDataAuth,
	}
	return info, nil
}

func (c *WompiClient) CreateCardToken(req *domain.WompiCardTokenRequest) (*domain.WompiCardTokenResponse, error) {
	url := fmt.Sprintf("%s/tokens/cards", c.BaseURL)
	body, _ := json.Marshal(req)
	httpReq, _ := http.NewRequest("POST", url, bytes.NewBuffer(body))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.PublicKey)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result domain.WompiCardTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}
