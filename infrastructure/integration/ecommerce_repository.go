package infrastructure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	customerDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/customer"
	itemDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
)

type EcommerceRepository interface {
	GetItems() ([]itemDomain.Item, error)
	GetItemByID(id string) (*itemDomain.Item, error)
	GetCustomers() ([]customerDomain.Customer, error)
	GetCustomerByID(id string) (*customerDomain.Customer, error)
}

type ecommerceRepository struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

func NewEcommerceRepository() (EcommerceRepository, error) {
	baseURL := os.Getenv("KIVIO_ECOMMERCE_API_URL")
	if baseURL == "" {
		return nil, fmt.Errorf("KIVIO_ECOMMERCE_API_URL environment variable is required")
	}

	apiKey := os.Getenv("KIVIO_ECOMMERCE_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("KIVIO_ECOMMERCE_API_KEY environment variable is required")
	}

	return &ecommerceRepository{
		baseURL: baseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: time.Second * 30,
		},
	}, nil
}

func (r *ecommerceRepository) GetItems() ([]itemDomain.Item, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/products", r.baseURL), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", r.apiKey))
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var apiProducts []struct {
		ID          string    `json:"id"`
		Name        string    `json:"name"`
		Description string    `json:"description"`
		Price       float64   `json:"price"`
		SKU         string    `json:"sku"`
		Stock       int       `json:"stock"`
		CreatedAt   time.Time `json:"createdAt"`
		UpdatedAt   time.Time `json:"updatedAt"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiProducts); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	items := make([]itemDomain.Item, len(apiProducts))
	for i, p := range apiProducts {
		items[i] = itemDomain.Item{
			ItemId:        p.ID,
			Name:          p.Name,
			Description:   p.Description,
			ExternalId:    p.SKU,
			PointOfSaleId: "ecommerce", // You might want to make this configurable
			Url:           fmt.Sprintf("%s/products/%s", r.baseURL, p.ID),
			Source:        "ecommerce",
		}
	}

	return items, nil
}

func (r *ecommerceRepository) GetItemByID(id string) (*itemDomain.Item, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/products/%s", r.baseURL, id), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", r.apiKey))
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("product not found")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var apiProduct struct {
		ID          string    `json:"id"`
		Name        string    `json:"name"`
		Description string    `json:"description"`
		Price       float64   `json:"price"`
		SKU         string    `json:"sku"`
		Stock       int       `json:"stock"`
		CreatedAt   time.Time `json:"createdAt"`
		UpdatedAt   time.Time `json:"updatedAt"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiProduct); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	item := &itemDomain.Item{
		ItemId:        apiProduct.ID,
		Name:          apiProduct.Name,
		Description:   apiProduct.Description,
		ExternalId:    apiProduct.SKU,
		PointOfSaleId: "ecommerce", // You might want to make this configurable
		Url:           fmt.Sprintf("%s/products/%s", r.baseURL, apiProduct.ID),
		Source:        "ecommerce",
	}

	return item, nil
}

func (r *ecommerceRepository) GetCustomers() ([]customerDomain.Customer, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/customers", r.baseURL), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", r.apiKey))
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

func (r *ecommerceRepository) GetCustomerByID(id string) (*customerDomain.Customer, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/customers/%s", r.baseURL, id), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", r.apiKey))
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
