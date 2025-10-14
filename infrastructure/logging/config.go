package logging

import (
	"os"
	"strings"
)

type LokiConfig struct {
	Enabled     bool   `json:"enabled"`
	URL         string `json:"url"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	ServiceName string `json:"service_name"`
	Environment string `json:"environment"`
	LogLevel    string `json:"log_level"`
}

func GetLokiConfigFromEnv() *LokiConfig {
	return &LokiConfig{
		Enabled:     getEnvBool("LOKI_ENABLED", true),
		URL:         getEnv("LOKI_URL", ""),
		Username:    getEnv("LOKI_USERNAME", ""),
		Password:    getEnv("LOKI_PASSWORD", ""),
		ServiceName: getEnv("SERVICE_NAME", "kivio-auctions"),
		Environment: getEnv("ENVIRONMENT", "development"),
		LogLevel:    getEnv("LOG_LEVEL", "info"),
	}
}

func (c *LokiConfig) IsValid() bool {
	return c.Enabled && c.URL != "" && c.Username != "" && c.Password != ""
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		return strings.ToLower(value) == "true"
	}
	return defaultValue
}
