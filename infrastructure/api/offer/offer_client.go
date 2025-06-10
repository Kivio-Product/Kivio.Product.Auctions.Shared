package offer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

type OfferClient interface {
	GetToken(ctx context.Context, offerId string) (string, error)
	SendToken(ctx context.Context, offerId, token string) error
}

type offerClient struct {
	client  *http.Client
	baseURL string
	env     string
}

func NewOfferClient() OfferClient {
	return &offerClient{
		client:  &http.Client{},
		baseURL: getBaseURL(),
		env:     getEnv(),
	}
}

func (c *offerClient) GetToken(ctx context.Context, offerId string) (string, error) {
	tokenURL := fmt.Sprintf("%s/v1/%s/token", c.baseURL, offerId)
	req, err := http.NewRequestWithContext(ctx, "GET", tokenURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get token: status code %d", resp.StatusCode)
	}

	var tokenResponse struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	return tokenResponse.Data.Token, nil
}

func (c *offerClient) SendToken(ctx context.Context, offerId, token string) error {
	sendTokenURL := fmt.Sprintf("%s/v1/send-token", c.baseURL)
	sendTokenBody := map[string]string{
		"offer_id":   offerId,
		"enviroment": c.env,
	}
	body, err := json.Marshal(sendTokenBody)
	if err != nil {
		return fmt.Errorf("failed to marshal send token request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", sendTokenURL, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("failed to create send token request: %w", err)
	}
	req.Header.Set("Authorization", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to send token: status code %d", resp.StatusCode)
	}

	return nil
}

func getBaseURL() string {
	return os.Getenv("API_OFFERS_BASE_URL")
}

func getEnv() string {
	return os.Getenv("AUCTIONS_ENV")
}
