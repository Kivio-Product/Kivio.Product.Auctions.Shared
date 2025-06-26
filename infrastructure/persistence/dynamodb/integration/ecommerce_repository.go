package infrastructure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	customerDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/customer"
	itemDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
	"github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/api/ecommerce"
)

type EcommerceRepository interface {
	GetItems(baseUrl, apiKey string, page, limit int) ([]itemDomain.Item, error)
	GetItemsRaw(baseUrl, apiKey string, page, limit int, publishedStatus bool) ([]byte, error)
	GetItemByID(baseUrl, apiKey, itemId string) (*itemDomain.Item, error)
	GetItemByIDRaw(baseUrl, apiKey, itemId string) ([]byte, error)
	GetCustomers(baseUrl, apiKey string) ([]customerDomain.Customer, error)
	GetCustomerByID(baseUrl, apiKey, id string) (*customerDomain.Customer, error)
	GetApiKey(username, password, tokenUrl string) (string, error)
	UpdateItemStock(baseUrl, apiKey, itemId string, newStock int64) error
	GetAllItemsRaw(baseUrl, apiKey string) ([]byte, error)
}

type ecommerceRepository struct {
	client ecommerce.EcommerceClient
}

func NewEcommerceRepository() EcommerceRepository {
	return &ecommerceRepository{
		client: ecommerce.NewEcommerceClient(),
	}
}

func (r *ecommerceRepository) GetApiKey(username, password, tokenUrl string) (string, error) {
	return r.client.GetApiKey(username, password, tokenUrl)
}

func (r *ecommerceRepository) GetItems(baseUrl, apiKey string, page, limit int) ([]itemDomain.Item, error) {
	respBody, err := r.client.GetItems(baseUrl, apiKey, page, limit, true)
	if err != nil {
		return nil, err
	}

	type Product struct {
		ID          int    `json:"id"`
		Name        string `json:"name"`
		Description string `json:"short_description"`
		Images      []struct {
			Src string `json:"src"`
		} `json:"images"`
		Published bool `json:"published"`
	}

	type ApiResponse struct {
		Products []Product `json:"products"`
		Total    int       `json:"total"`
		Pages    int       `json:"pages"`
	}

	var apiResponse ApiResponse
	if err := json.Unmarshal(respBody, &apiResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal items: %w", err)
	}

	var items []itemDomain.Item
	for _, product := range apiResponse.Products {
		if !product.Published {
			continue
		}
		var imageURL string
		if len(product.Images) > 0 {
			imageURL = product.Images[0].Src
		}

		item := itemDomain.Item{
			ItemId:      fmt.Sprintf("kivio-ecommerce∼%d", product.ID),
			Name:        product.Name,
			Description: product.Description,
			ExternalId:  fmt.Sprintf("kivio-ecommerce∼%d", product.ID),
			Url:         imageURL,
		}
		items = append(items, item)
	}

	return items, nil
}

func (r *ecommerceRepository) GetItemsRaw(baseUrl, apiKey string, page, limit int, publishedStatus bool) ([]byte, error) {
	return r.client.GetItems(baseUrl, apiKey, page, limit, publishedStatus)
}

func (r *ecommerceRepository) GetItemByID(baseUrl, apiKey, itemId string) (*itemDomain.Item, error) {
	itemId = strings.TrimPrefix(itemId, "kivio-ecommerce∼")
	respBody, err := r.client.GetItemByID(baseUrl, apiKey, itemId)
	if err != nil {
		return nil, err
	}

	type Image struct {
		Src string `json:"src"`
	}

	type Product struct {
		ID               int     `json:"id"`
		Name             string  `json:"name"`
		ShortDescription string  `json:"short_description"`
		FullDescription  string  `json:"full_description"`
		Price            float64 `json:"price"`
		Images           []Image `json:"images"`
		SKU              string  `json:"sku"`
	}

	type ApiResponse struct {
		Products []Product `json:"products"`
	}

	var apiResponse ApiResponse
	if err := json.Unmarshal(respBody, &apiResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if len(apiResponse.Products) == 0 {
		return nil, fmt.Errorf("product not found")
	}

	product := apiResponse.Products[0]

	var imageURL string
	if len(product.Images) > 0 {
		imageURL = product.Images[0].Src
	}

	item := &itemDomain.Item{
		ItemId:      fmt.Sprintf("kivio-ecommerce∼%d", product.ID),
		Name:        product.Name,
		Description: product.ShortDescription,
		ExternalId:  product.SKU,
		Source:      "kivio ecommerce",
		Url:         imageURL,
	}

	return item, nil
}

func (r *ecommerceRepository) GetItemByIDRaw(baseUrl, apiKey, itemId string) ([]byte, error) {
	itemId = strings.TrimPrefix(itemId, "kivio-ecommerce∼")
	return r.client.GetItemByID(baseUrl, apiKey, itemId)
}

func (r *ecommerceRepository) GetCustomers(baseUrl, apiKey string) ([]customerDomain.Customer, error) {
	respBody, err := r.client.GetCustomers(baseUrl, apiKey)
	if err != nil {
		return nil, err
	}

	var customers []customerDomain.Customer
	if err := json.Unmarshal(respBody, &customers); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return customers, nil
}

func (r *ecommerceRepository) GetCustomerByID(baseUrl, apiKey, id string) (*customerDomain.Customer, error) {
	respBody, err := r.client.GetCustomerByID(baseUrl, apiKey, id)
	if err != nil {
		return nil, err
	}

	var customer customerDomain.Customer
	if err := json.Unmarshal(respBody, &customer); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return &customer, nil
}

func (r *ecommerceRepository) UpdateItemStock(baseUrl, apiKey, itemId string, newStock int64) error {
	url := fmt.Sprintf("%s/api/products/%s", baseUrl, itemId)
	payload := map[string]interface{}{
		"product": map[string]interface{}{
			"stock_quantity": newStock,
		},
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("PUT", url, strings.NewReader(string(jsonPayload)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return fmt.Errorf("failed to update stock, status code: %d", resp.StatusCode)
	}
	return nil
}

func (r *ecommerceRepository) GetAllItemsRaw(baseUrl, apiKey string) ([]byte, error) {
	return r.client.GetAllItems(baseUrl, apiKey)
}
