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

	fmt.Printf("DEBUG: Siigo client initialization - baseURL: %s, username: %s, accessKey length: %d\n",
		baseURL, username, len(accessKey))

	if baseURL == "" {
		fmt.Println("WARNING: SIIGO_API_BASE_URL is empty")
	}
	if username == "" {
		fmt.Println("WARNING: SIIGO_API_USERNAME is empty")
	}
	if accessKey == "" {
		fmt.Println("WARNING: SIIGO_API_ACCESS_KEY is empty")
	}

	return &siigoClient{
		baseURL:   baseURL,
		username:  username,
		accessKey: accessKey,
		httpClient: &http.Client{
			Timeout: 45 * time.Second,
		},
	}
}

func (c *siigoClient) Authenticate(ctx context.Context) error {
	fmt.Printf("DEBUG: Starting authentication - token exists: %t, token expired: %t\n",
		c.accessToken != "", time.Now().After(c.tokenExpiry))

	if c.accessToken != "" && time.Now().Before(c.tokenExpiry) {
		fmt.Println("DEBUG: Using existing valid token")
		return nil
	}

	fmt.Printf("DEBUG: Preparing auth request with username: %s, accessKey length: %d\n",
		c.username, len(c.accessKey))

	authReq := authRequest{
		Username:  c.username,
		AccessKey: c.accessKey,
	}

	jsonData, err := json.Marshal(authReq)
	if err != nil {
		fmt.Printf("DEBUG: Error marshaling auth request: %v\n", err)
		return fmt.Errorf("error marshaling auth request: %w", err)
	}

	authURL := c.baseURL + "/auth"
	fmt.Printf("DEBUG: Making auth request to: %s\n", authURL)

	select {
	case <-ctx.Done():
		fmt.Printf("DEBUG: Context already cancelled before request: %v\n", ctx.Err())
		return fmt.Errorf("context cancelled before auth request: %w", ctx.Err())
	default:
	}

	if deadline, ok := ctx.Deadline(); ok {
		fmt.Printf("DEBUG: Context deadline: %v (time remaining: %v)\n", deadline, time.Until(deadline))
	} else {
		fmt.Println("DEBUG: Context has no deadline")
	}

	req, err := http.NewRequestWithContext(ctx, "POST", authURL, bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("DEBUG: Error creating auth request: %v\n", err)
		return fmt.Errorf("error creating auth request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Partner-Id", "kivio")

	fmt.Println("DEBUG: About to make HTTP request...")
	start := time.Now()
	resp, err := c.httpClient.Do(req)
	duration := time.Since(start)

	if err != nil {
		fmt.Printf("DEBUG: HTTP request failed after %v: %v\n", duration, err)
		return fmt.Errorf("error making auth request: %w", err)
	}
	defer resp.Body.Close()

	fmt.Printf("DEBUG: HTTP request completed in %v with status: %d\n", duration, resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("DEBUG: Auth failed with status %d, body: %s\n", resp.StatusCode, string(body))
		return fmt.Errorf("auth failed with status %d: %s", resp.StatusCode, string(body))
	}

	var authResp authResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		fmt.Printf("DEBUG: Error decoding auth response: %v\n", err)
		return fmt.Errorf("error decoding auth response: %w", err)
	}

	c.accessToken = authResp.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(authResp.ExpiresIn-300) * time.Second)

	fmt.Printf("DEBUG: Authentication successful - token expires at: %v\n", c.tokenExpiry)

	return nil
}

func (c *siigoClient) CreateInvoice(ctx context.Context, invoice *invoiceDomain.SiigoInvoice) (*invoiceDomain.SiigoInvoiceResponse, error) {

	if err := c.Authenticate(ctx); err != nil {
		fmt.Printf("DEBUG: CreateInvoice authentication failed: %v\n", err)
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	fmt.Println("DEBUG: Marshaling invoice data...")
	jsonData, err := json.Marshal(invoice)
	if err != nil {
		fmt.Printf("DEBUG: Error marshaling invoice: %v\n", err)
		return nil, fmt.Errorf("error marshaling invoice: %w", err)
	}

	invoiceURL := c.baseURL + "/v1/invoices"
	fmt.Printf("DEBUG: Making invoice request to: %s\n", invoiceURL)

	select {
	case <-ctx.Done():
		fmt.Printf("DEBUG: Context already cancelled before invoice request: %v\n", ctx.Err())
		return nil, fmt.Errorf("context cancelled before invoice request: %w", ctx.Err())
	default:
	}

	if deadline, ok := ctx.Deadline(); ok {
		fmt.Printf("DEBUG: Context deadline: %v (time remaining: %v)\n", deadline, time.Until(deadline))
	} else {
		fmt.Println("DEBUG: Context has no deadline")
	}

	req, err := http.NewRequestWithContext(ctx, "POST", invoiceURL, bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("DEBUG: Error creating invoice request: %v\n", err)
		return nil, fmt.Errorf("error creating invoice request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Partner-Id", "kivio")

	fmt.Println("DEBUG: About to make invoice HTTP request...")
	start := time.Now()
	resp, err := c.httpClient.Do(req)
	duration := time.Since(start)

	if err != nil {
		fmt.Printf("DEBUG: Invoice HTTP request failed after %v: %v\n", duration, err)
		return nil, fmt.Errorf("error making invoice request: %w", err)
	}
	defer resp.Body.Close()

	fmt.Printf("DEBUG: Invoice HTTP request completed in %v with status: %d\n", duration, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("DEBUG: Error reading invoice response: %v\n", err)
		return nil, fmt.Errorf("error reading response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		fmt.Printf("DEBUG: Invoice creation failed with status %d, body: %s\n", resp.StatusCode, string(body))
		return nil, fmt.Errorf("invoice creation failed with status %d: %s", resp.StatusCode, string(body))
	}

	fmt.Println("DEBUG: Decoding invoice response...")
	var invoiceResp invoiceDomain.SiigoInvoiceResponse
	if err := json.Unmarshal(body, &invoiceResp); err != nil {
		fmt.Printf("DEBUG: Error decoding invoice response: %v\n", err)
		return nil, fmt.Errorf("error decoding invoice response: %w", err)
	}

	fmt.Printf("DEBUG: Invoice creation successful - ID: %s\n", invoiceResp.ID)

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
	req.Header.Set("Partner-Id", "kivio")

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
