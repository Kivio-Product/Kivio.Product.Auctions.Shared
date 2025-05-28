package google_studio

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

type GoogleStudioClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

type GenerateContentRequest struct {
	Contents []Content `json:"contents"`
}

type Content struct {
	Parts []Part `json:"parts"`
}

type Part struct {
	Text string `json:"text"`
}

type GenerateContentResponse struct {
	Candidates []Candidate `json:"candidates"`
}

type Candidate struct {
	Content Content `json:"content"`
}

func NewGoogleStudioClient() *GoogleStudioClient {
	baseURL := os.Getenv("GOOGLE_STUDIO_API_URL")
	if baseURL == "" {
		baseURL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"
	}

	apiKey := os.Getenv("GOOGLE_STUDIO_API_KEY")
	if apiKey == "" {
		panic("GOOGLE_STUDIO_API_KEY environment variable is required")
	}

	return &GoogleStudioClient{
		baseURL:    baseURL,
		apiKey:     apiKey,
		httpClient: &http.Client{},
	}
}

func (c *GoogleStudioClient) GenerateContent(prompt string) (string, error) {
	url := fmt.Sprintf("%s?key=%s", c.baseURL, c.apiKey)

	reqBody := GenerateContentRequest{
		Contents: []Content{
			{
				Parts: []Part{
					{
						Text: prompt,
					},
				},
			},
		},
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("error marshaling request body: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var response GenerateContentResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", fmt.Errorf("error decoding response: %w", err)
	}

	if len(response.Candidates) == 0 || len(response.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("no content in response")
	}

	return response.Candidates[0].Content.Parts[0].Text, nil
}
