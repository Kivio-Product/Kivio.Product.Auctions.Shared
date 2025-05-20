package infrastructure

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/user"
)

type Identity struct {
	IdentityID   string                 `json:"identity_id"`
	ID           string                 `json:"id"`
	UserID       string                 `json:"user_id"`
	IdentityData map[string]interface{} `json:"identity_data"`
	Provider     string                 `json:"provider"`
	LastSignInAt time.Time              `json:"last_sign_in_at"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
	Email        string                 `json:"email"`
}

type AppMetadata struct {
	Provider  string   `json:"provider"`
	Providers []string `json:"providers"`
	Role      string   `json:"role"`
}

type UserMetadata struct {
	EmailVerified bool `json:"email_verified"`
}

type AuthUser struct {
	ID               string       `json:"id"`
	Aud              string       `json:"aud"`
	Role             string       `json:"role"`
	Email            string       `json:"email"`
	EmailConfirmedAt time.Time    `json:"email_confirmed_at"`
	Phone            string       `json:"phone"`
	ConfirmedAt      time.Time    `json:"confirmed_at"`
	LastSignInAt     time.Time    `json:"last_sign_in_at"`
	AppMetadata      AppMetadata  `json:"app_metadata"`
	UserMetadata     UserMetadata `json:"user_metadata"`
	Identities       []Identity   `json:"identities"`
	CreatedAt        time.Time    `json:"created_at"`
	UpdatedAt        time.Time    `json:"updated_at"`
	IsAnonymous      bool         `json:"is_anonymous"`
}

type AuthResponse struct {
	AccessToken  string   `json:"access_token"`
	TokenType    string   `json:"token_type"`
	ExpiresIn    int      `json:"expires_in"`
	ExpiresAt    int64    `json:"expires_at"`
	RefreshToken string   `json:"refresh_token"`
	User         AuthUser `json:"user"`
}

type UserRepository interface {
	GetAllUsers() ([]domain.User, error)
	AuthenticateUser(email, password string) (*AuthResponse, error)
	SignOut(token string) error
	ResetPassword(email string) error
	SetNewPassword(token, password string) error
	GetSessionByRefreshToken(refreshToken string) (*AuthResponse, error)
	RefreshSession(refreshToken string) (*AuthResponse, error)
}

type userRepository struct {
	supabaseURL    string
	serviceRoleKey string
	apiKey         string
}

func NewUserRepository() UserRepository {
	return &userRepository{
		supabaseURL:    os.Getenv("SUPABASE_URL"),
		serviceRoleKey: os.Getenv("SERVICE_ROLE_KEY"),
		apiKey:         os.Getenv("SUPABASE_KEY"),
	}
}

func (r *userRepository) GetAllUsers() ([]domain.User, error) {
	req, err := http.NewRequest("GET", r.supabaseURL+"/rest/v1/profiles", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("apikey", r.serviceRoleKey)
	req.Header.Set("Authorization", "Bearer "+r.serviceRoleKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		return nil, err
	}

	fmt.Print(err)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error: received status code %d", resp.StatusCode)
	}

	var users []domain.User

	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		fmt.Print(err)
		return nil, err
	}

	return users, nil
}

func (r *userRepository) AuthenticateUser(email, password string) (*AuthResponse, error) {
	payload, err := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
	})
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/auth/v1/token?grant_type=password", r.supabaseURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}

	req.Header.Set("apikey", r.apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := json.Marshal(map[string]string{"error": fmt.Sprintf("Authentication failed with status code: %d", resp.StatusCode)})
		return nil, fmt.Errorf(string(bodyBytes))
	}

	var authResponse AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
		return nil, err
	}

	return &authResponse, nil
}

func (r *userRepository) SignOut(token string) error {
	url := fmt.Sprintf("%s/auth/v1/logout", r.supabaseURL)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("apikey", r.apiKey)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("error signing out: received status code %d", resp.StatusCode)
	}

	return nil
}

func (r *userRepository) ResetPassword(email string) error {
	payload, err := json.Marshal(map[string]string{
		"email": email,
	})
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/auth/v1/recover", r.supabaseURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}

	req.Header.Set("apikey", r.apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("error resetting password: received status code %d", resp.StatusCode)
	}

	return nil
}

func (r *userRepository) SetNewPassword(token, password string) error {
	payload, err := json.Marshal(map[string]string{
		"password": password,
	})
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/auth/v1/user", r.supabaseURL)
	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}

	req.Header.Set("apikey", r.apiKey)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("error setting new password: received status code %d", resp.StatusCode)
	}

	return nil
}

func (r *userRepository) GetSessionByRefreshToken(refreshToken string) (*AuthResponse, error) {
	payload, err := json.Marshal(map[string]string{
		"refresh_token": refreshToken,
	})
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/auth/v1/token?grant_type=refresh_token", r.supabaseURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}

	req.Header.Set("apikey", r.apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error getting session: received status code %d", resp.StatusCode)
	}

	var authResponse AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
		return nil, err
	}

	return &authResponse, nil
}

func (r *userRepository) RefreshSession(refreshToken string) (*AuthResponse, error) {
	return r.GetSessionByRefreshToken(refreshToken)
}
