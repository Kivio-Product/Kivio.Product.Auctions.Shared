package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/logging"
)

// ConsoleLogger implements Logger interface for console output (fallback)
type ConsoleLogger struct {
	serviceName string
	logLevel    string
}

// NewConsoleLogger creates a new console logger
func NewConsoleLogger(serviceName, logLevel string) *ConsoleLogger {
	return &ConsoleLogger{
		serviceName: serviceName,
		logLevel:    logLevel,
	}
}

// Debug implements Logger.Debug
func (c *ConsoleLogger) Debug(ctx context.Context, message string, fields map[string]interface{}) {
	if !c.shouldLog(logging.DebugLevel) {
		return
	}
	c.log(logging.DebugLevel, message, "", fields)
}

// Info implements Logger.Info
func (c *ConsoleLogger) Info(ctx context.Context, message string, fields map[string]interface{}) {
	if !c.shouldLog(logging.InfoLevel) {
		return
	}
	c.log(logging.InfoLevel, message, "", fields)
}

// Warn implements Logger.Warn
func (c *ConsoleLogger) Warn(ctx context.Context, message string, fields map[string]interface{}) {
	if !c.shouldLog(logging.WarnLevel) {
		return
	}
	c.log(logging.WarnLevel, message, "", fields)
}

// Error implements Logger.Error
func (c *ConsoleLogger) Error(ctx context.Context, message string, err error, fields map[string]interface{}) {
	if !c.shouldLog(logging.ErrorLevel) {
		return
	}

	errorMsg := ""
	if err != nil {
		errorMsg = err.Error()
	}
	c.log(logging.ErrorLevel, message, errorMsg, fields)
}

// WithService implements Logger.WithService
func (c *ConsoleLogger) WithService(serviceName string) logging.Logger {
	return &ConsoleLogger{
		serviceName: serviceName,
		logLevel:    c.logLevel,
	}
}

// log outputs to console
func (c *ConsoleLogger) log(level logging.LogLevel, message, errorMsg string, fields map[string]interface{}) {
	entry := logging.LogEntry{
		Level:     level,
		Message:   message,
		Timestamp: time.Now(),
		Service:   c.serviceName,
		Context:   fields,
		Error:     errorMsg,
	}

	// Convert to JSON for structured logging
	jsonData, err := json.Marshal(entry)
	if err != nil {
		log.Printf("[%s] %s - %s (JSON marshal error: %v)",
			string(level), c.serviceName, message, err)
		return
	}

	// Output to console
	fmt.Printf("%s\n", string(jsonData))
}

// shouldLog checks if the log level should be logged
func (c *ConsoleLogger) shouldLog(level logging.LogLevel) bool {
	switch c.logLevel {
	case "debug":
		return true
	case "info":
		return level != logging.DebugLevel
	case "warn":
		return level == logging.WarnLevel || level == logging.ErrorLevel
	case "error":
		return level == logging.ErrorLevel
	default:
		return true
	}
}