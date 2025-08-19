package siigo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	invoiceDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/invoice"
)

type SiigoClient interface {
	CreateInvoice(ctx context.Context, invoice *invoiceDomain.SiigoInvoice) (*invoiceDomain.SiigoInvoiceResponse, error)
	GetInvoice(ctx context.Context, invoiceID string) (*invoiceDomain.SiigoInvoiceResponse, error)
	Authenticate(ctx context.Context) error
}

type siigoClient struct {
	baseURL     string
	username    string
	accessKey   string
	httpClient  *http.Client
	accessToken string
	tokenExpiry time.Time
}

type authRequest struct {
	Username  string `json:"username"`
	AccessKey string `json:"access_key"`
}

type authResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func NewSiigoClient() SiigoClient {

	baseURL := os.Getenv("SIIGO_API_BASE_URL")
	username := os.Getenv("SIIGO_API_USERNAME")
	accessKey := os.Getenv("SIIGO_API_ACCESS_KEY")

	return &siigoClient{
		baseURL:   baseURL,
		username:  username,
		accessKey: accessKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *siigoClient) Authenticate(ctx context.Context) error {
	if c.accessToken != "" && time.Now().Before(c.tokenExpiry) {
		return nil
	}

	authReq := authRequest{
		Username:  c.username,
		AccessKey: c.accessKey,
	}

	jsonData, err := json.Marshal(authReq)
	if err != nil {
		return fmt.Errorf("error marshaling auth request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/auth", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("error creating auth request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Partner-Id", "kivio-auctions")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("error making auth request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("auth failed with status %d: %s", resp.StatusCode, string(body))
	}

	var authResp authResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return fmt.Errorf("error decoding auth response: %w", err)
	}

	c.accessToken = authResp.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(authResp.ExpiresIn-300) * time.Second)

	return nil
}

func (c *siigoClient) CreateInvoice(ctx context.Context, invoice *invoiceDomain.SiigoInvoice) (*invoiceDomain.SiigoInvoiceResponse, error) {
	if err := c.Authenticate(ctx); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	jsonData, err := json.Marshal(invoice)
	if err != nil {
		return nil, fmt.Errorf("error marshaling invoice: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/v1/invoices", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("error creating invoice request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Partner-Id", "kivio-auctions")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making invoice request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("invoice creation failed with status %d: %s", resp.StatusCode, string(body))
	}

	var invoiceResp invoiceDomain.SiigoInvoiceResponse
	if err := json.Unmarshal(body, &invoiceResp); err != nil {
		return nil, fmt.Errorf("error decoding invoice response: %w", err)
	}

	return &invoiceResp, nil
}

func (c *siigoClient) GetInvoice(ctx context.Context, invoiceID string) (*invoiceDomain.SiigoInvoiceResponse, error) {
	if err := c.Authenticate(ctx); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/v1/invoices/"+invoiceID, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating get invoice request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Partner-Id", "kivio-auctions")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making get invoice request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get invoice failed with status %d: %s", resp.StatusCode, string(body))
	}

	var invoiceResp invoiceDomain.SiigoInvoiceResponse
	if err := json.Unmarshal(body, &invoiceResp); err != nil {
		return nil, fmt.Errorf("error decoding invoice response: %w", err)
	}

	return &invoiceResp, nil
}
