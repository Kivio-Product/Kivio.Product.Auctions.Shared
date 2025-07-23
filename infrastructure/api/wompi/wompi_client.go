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
	BaseURL    string
	PublicKey  string
	PrivateKey string
}

func NewWompiClient() *WompiClient {
	return &WompiClient{
		BaseURL:    os.Getenv("WOMPI_API_URL"),
		PublicKey:  os.Getenv("WOMPI_PUBLIC_KEY"),
		PrivateKey: os.Getenv("WOMPI_PRIVATE_KEY"),
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

func (c *WompiClient) CreatePaymentSource(req *domain.WompiPaymentSourceRequest) (*domain.WompiPaymentSourceResponse, error) {
	url := fmt.Sprintf("%s/payment_sources", c.BaseURL)
	body, _ := json.Marshal(req)
	httpReq, _ := http.NewRequest("POST", url, bytes.NewBuffer(body))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.PrivateKey)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result domain.WompiPaymentSourceResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *WompiClient) CreateTransaction(req *domain.WompiTransactionRequest) (*domain.WompiTransactionResponse, error) {
	url := fmt.Sprintf("%s/transactions", c.BaseURL)
	body, _ := json.Marshal(req)
	httpReq, _ := http.NewRequest("POST", url, bytes.NewBuffer(body))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.PrivateKey)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		var errBody bytes.Buffer
		errBody.ReadFrom(resp.Body)
		return nil, fmt.Errorf("error en /transactions: status %d, body: %s", resp.StatusCode, errBody.String())
	}

	var result domain.WompiTransactionResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *WompiClient) CreateNequiToken(phoneNumber, acceptanceToken, acceptancePersonalAuth string) (*domain.WompiNequiTokenResponse, error) {
	url := fmt.Sprintf("%s/tokens/nequi", c.BaseURL)
	payload := map[string]string{
		"phone_number":         phoneNumber,
		"acceptance_token":     acceptanceToken,
		"accept_personal_auth": acceptancePersonalAuth,
	}
	body, _ := json.Marshal(payload)
	httpReq, _ := http.NewRequest("POST", url, bytes.NewBuffer(body))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.PublicKey)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errBody bytes.Buffer
		errBody.ReadFrom(resp.Body)
		return nil, fmt.Errorf("error en /tokens/nequi: status %d, body: %s", resp.StatusCode, errBody.String())
	}

	var result domain.WompiNequiTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}
