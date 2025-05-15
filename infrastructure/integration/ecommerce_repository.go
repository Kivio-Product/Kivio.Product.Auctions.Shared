package infrastructure

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	customerDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/customer"
	itemDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
)

type EcommerceRepository interface {
	GetItems(baseUrl, apiKey string) ([]itemDomain.Item, error)
	GetItemByID(baseUrl, apiKey, itemId string) (*itemDomain.Item, error)
	GetCustomers(baseUrl, apiKey string) ([]customerDomain.Customer, error)
	GetCustomerByID(baseUrl, apiKey, id string) (*customerDomain.Customer, error)
	GetApiKey(username, password, tokenUrl string) (string, error)
}

type ecommerceRepository struct {
	httpClient *http.Client
}

func NewEcommerceRepository() EcommerceRepository {
	return &ecommerceRepository{
		httpClient: &http.Client{
			Timeout: time.Second * 30,
		},
	}
}

func (r *ecommerceRepository) GetApiKey(username, password, tokenUrl string) (string, error) {
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

	resp, err := r.httpClient.Do(req)
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
		return "", errors.New("API key not found in response")
	}

	return apiKey, nil
}

func (r *ecommerceRepository) GetItems(baseUrl, apiKey string) ([]itemDomain.Item, error) {
	url := fmt.Sprintf("%s/api/products?Limit=2", baseUrl)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get items, status code: %d", resp.StatusCode)
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	type Product struct {
		ID          int    `json:"id"`
		Name        string `json:"name"`
		Description string `json:"short_description"`
	}

	type ApiResponse struct {
		Products []Product `json:"products"`
	}

	var apiResponse ApiResponse
	if err := json.Unmarshal(respBody, &apiResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal items: %w", err)
	}

	var items []itemDomain.Item
	for _, product := range apiResponse.Products {
		item := itemDomain.Item{
			ItemId:      fmt.Sprintf("kivio-ecommerce∼%d", product.ID),
			Name:        product.Name,
			Description: product.Description,
			ExternalId:  fmt.Sprintf("kivio-ecommerce∼%d", product.ID),
		}
		items = append(items, item)
	}

	return items, nil
}

func (r *ecommerceRepository) GetItemByID(baseUrl, apiKey, itemId string) (*itemDomain.Item, error) {
	url := fmt.Sprintf("%s/items/%s", baseUrl, itemId)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get item, status code: %d", resp.StatusCode)
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var item itemDomain.Item
	if err := json.Unmarshal(respBody, &item); err != nil {
		return nil, fmt.Errorf("failed to unmarshal item: %w", err)
	}

	return &item, nil
}

func (r *ecommerceRepository) GetCustomers(baseUrl, apiKey string) ([]customerDomain.Customer, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/customers", baseUrl), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var customers []customerDomain.Customer
	if err := json.NewDecoder(resp.Body).Decode(&customers); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return customers, nil
}

func (r *ecommerceRepository) GetCustomerByID(baseUrl, apiKey, id string) (*customerDomain.Customer, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/customers/%s", baseUrl, id), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.httpClient.Do(req)
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

	var customer customerDomain.Customer
	if err := json.NewDecoder(resp.Body).Decode(&customer); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return &customer, nil
}
