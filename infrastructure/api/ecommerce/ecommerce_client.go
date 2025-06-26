package ecommerce

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

type EcommerceClient interface {
	GetApiKey(username, password, tokenUrl string) (string, error)
	GetItems(baseUrl, apiKey string, page, limit int, publishedStatus bool) ([]byte, error)
	GetItemByID(baseUrl, apiKey, itemId string) ([]byte, error)
	GetCustomers(baseUrl, apiKey string) ([]byte, error)
	GetCustomerByID(baseUrl, apiKey, id string) ([]byte, error)
	GetAllItems(baseUrl, apiKey string) ([]byte, error)
}

type ecommerceClient struct {
	httpClient *http.Client
}

func NewEcommerceClient() EcommerceClient {
	return &ecommerceClient{
		httpClient: &http.Client{
			Timeout: time.Second * 30,
		},
	}
}

func (c *ecommerceClient) GetApiKey(username, password, tokenUrl string) (string, error) {
	payload := map[string]interface{}{
		"guest":       true,
		"username":    username,
		"password":    password,
		"remember_me": true,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", tokenUrl, bytes.NewBuffer(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("accept", "text/plain")
	req.Header.Set("Content-Type", "application/json-patch+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get API key, status code: %d", resp.StatusCode)
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("failed to unmarshal response: %w", err)
	}

	apiKey, ok := result["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("API key not found in response")
	}

	return apiKey, nil
}

func (c *ecommerceClient) GetItems(baseUrl, apiKey string, page, limit int, publishedStatus bool) ([]byte, error) {
	url := fmt.Sprintf("%s/api/products?Page=%d&Limit=%d&PublishedStatus=%t", baseUrl, page, limit, publishedStatus)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get items, status code: %d", resp.StatusCode)
	}

	return ioutil.ReadAll(resp.Body)
}

func (c *ecommerceClient) GetItemByID(baseUrl, apiKey, itemId string) ([]byte, error) {
	fmt.Println("Fetching item by ID:", itemId, "from API URL:", baseUrl)
	url := fmt.Sprintf("%s/api/products/%s", baseUrl, itemId)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))

	resp, err := c.httpClient.Do(req)
	fmt.Println("Request sent to:", url)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get item, status code: %d", resp.StatusCode)
	}

	fmt.Println("Response status code:", resp.Body)

	return ioutil.ReadAll(resp.Body)
}

func (c *ecommerceClient) GetCustomers(baseUrl, apiKey string) ([]byte, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/customers", baseUrl), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return ioutil.ReadAll(resp.Body)
}

func (c *ecommerceClient) GetCustomerByID(baseUrl, apiKey, id string) ([]byte, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/customers/%s", baseUrl, id), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("customer not found")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return ioutil.ReadAll(resp.Body)
}

func (c *ecommerceClient) GetAllItems(baseUrl, apiKey string) ([]byte, error) {
	url := fmt.Sprintf("%s/api/products", baseUrl)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get all items, status code: %d", resp.StatusCode)
	}

	return ioutil.ReadAll(resp.Body)
}
