package logging

import (
	"os"
	"strconv"

	domainLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/logging"
)

type LoggerFactory struct{}

func NewLoggerFactory() *LoggerFactory {
	return &LoggerFactory{}
}

func (f *LoggerFactory) CreateLogger() (domainLogging.Logger, error) {
	config := f.createConfigFromEnv()
	return NewLokiLogger(config)
}

func (f *LoggerFactory) CreateLoggerWithConfig(config domainLogging.Config) (domainLogging.Logger, error) {
	return NewLokiLogger(config)
}

func (f *LoggerFactory) createConfigFromEnv() domainLogging.Config {
	config := domainLogging.Config{
		LokiURL:       getEnvWithDefault("LOKI_URL", ""),
		ServiceName:   getEnvWithDefault("SERVICE_NAME", "kivio-auctions-shared"),
		Environment:   getEnvWithDefault("ENVIRONMENT", "development"),
		LogLevel:      f.parseLogLevel(getEnvWithDefault("LOG_LEVEL", "info")),
		EnableConsole: getBoolEnvWithDefault("ENABLE_CONSOLE_LOGGING", true),
	}
	
	return config
}

func (f *LoggerFactory) parseLogLevel(level string) domainLogging.LogLevel {
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