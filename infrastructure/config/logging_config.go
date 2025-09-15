package config

import (
	"fmt"
	"os"
	"strconv"

	domainLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/logging"
)

type LoggingConfig struct {
	Loki      LokiConfig      `json:"loki"`
	Service   ServiceConfig   `json:"service"`
	Console   ConsoleConfig   `json:"console"`
	LogLevels LogLevelsConfig `json:"log_levels"`
}

type LokiConfig struct {
	Enabled  bool   `json:"enabled"`
	URL      string `json:"url"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`
	Timeout  int    `json:"timeout"` // seconds
}

type ServiceConfig struct {
	Name        string `json:"name"`
	Environment string `json:"environment"`
	Version     string `json:"version"`
}

type ConsoleConfig struct {
	Enabled bool `json:"enabled"`
	Format  string `json:"format"` // json, text
}

type LogLevelsConfig struct {
	Default        string `json:"default"`
	Domain         string `json:"domain"`
	Application    string `json:"application"`
	Infrastructure string `json:"infrastructure"`
}

func LoadLoggingConfig() (*LoggingConfig, error) {
	config := &LoggingConfig{
		Loki: LokiConfig{
			Enabled:  getBoolEnvWithDefault("LOKI_ENABLED", false),
			URL:      getEnvWithDefault("LOKI_URL", ""),
			Username: getEnvWithDefault("LOKI_USERNAME", ""),
			Password: getEnvWithDefault("LOKI_PASSWORD", ""),
			TenantID: getEnvWithDefault("LOKI_TENANT_ID", ""),
			Timeout:  getIntEnvWithDefault("LOKI_TIMEOUT", 30),
		},
		Service: ServiceConfig{
			Name:        getEnvWithDefault("SERVICE_NAME", "kivio-auctions-shared"),
			Environment: getEnvWithDefault("ENVIRONMENT", "development"),
			Version:     getEnvWithDefault("SERVICE_VERSION", "1.0.0"),
		},
		Console: ConsoleConfig{
			Enabled: getBoolEnvWithDefault("CONSOLE_LOGGING_ENABLED", true),
			Format:  getEnvWithDefault("CONSOLE_LOGGING_FORMAT", "json"),
		},
		LogLevels: LogLevelsConfig{
			Default:        getEnvWithDefault("LOG_LEVEL", "info"),
			Domain:         getEnvWithDefault("LOG_LEVEL_DOMAIN", ""),
			Application:    getEnvWithDefault("LOG_LEVEL_APPLICATION", ""),
			Infrastructure: getEnvWithDefault("LOG_LEVEL_INFRASTRUCTURE", ""),
		},
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid logging configuration: %w", err)
	}

	return config, nil
}

func (c *LoggingConfig) Validate() error {
	if c.Loki.Enabled && c.Loki.URL == "" {
		return fmt.Errorf("loki URL is required when loki is enabled")
	}

	if c.Service.Name == "" {
		return fmt.Errorf("service name is required")
	}

	if c.Service.Environment == "" {
		return fmt.Errorf("environment is required")
	}

	validLogLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}

	if !validLogLevels[c.LogLevels.Default] {
		return fmt.Errorf("invalid default log level: %s", c.LogLevels.Default)
	}

	return nil
}

func (c *LoggingConfig) ToDomainConfig() domainLogging.Config {
	return domainLogging.Config{
		LokiURL:       c.Loki.URL,
		ServiceName:   c.Service.Name,
		Environment:   c.Service.Environment,
		LogLevel:      c.parseLogLevel(c.LogLevels.Default),
		EnableConsole: c.Console.Enabled,
	}
}

func (c *LoggingConfig) parseLogLevel(level string) domainLogging.LogLevel {
	switch level {
	case "debug":
		return domainLogging.DEBUG
	case "info":
		return domainLogging.INFO
	case "warn":
		return domainLogging.WARN
	case "error":
		return domainLogging.ERROR
	default:
		return domainLogging.INFO
	}
}

func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getBoolEnvWithDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func getIntEnvWithDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}