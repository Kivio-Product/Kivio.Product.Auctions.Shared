package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/logging"
)

type ConsoleLogger struct {
	serviceName string
	logLevel    string
}

func NewConsoleLogger(serviceName, logLevel string) *ConsoleLogger {
	return &ConsoleLogger{
		serviceName: serviceName,
		logLevel:    logLevel,
	}
}

func (c *ConsoleLogger) Debug(ctx context.Context, message string, fields map[string]interface{}) {
	if !c.shouldLog(logging.DebugLevel) {
		return
	}
	c.log(logging.DebugLevel, message, "", fields)
}

func (c *ConsoleLogger) Info(ctx context.Context, message string, fields map[string]interface{}) {
	if !c.shouldLog(logging.InfoLevel) {
		return
	}
	c.log(logging.InfoLevel, message, "", fields)
}

func (c *ConsoleLogger) Warn(ctx context.Context, message string, fields map[string]interface{}) {
	if !c.shouldLog(logging.WarnLevel) {
		return
	}
	c.log(logging.WarnLevel, message, "", fields)
}

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

func (c *ConsoleLogger) WithService(serviceName string) logging.Logger {
	return &ConsoleLogger{
		serviceName: serviceName,
		logLevel:    c.logLevel,
	}
}

func (c *ConsoleLogger) log(level logging.LogLevel, message, errorMsg string, fields map[string]interface{}) {
	entry := logging.LogEntry{
		Level:     level,
		Message:   message,
		Timestamp: time.Now(),
		Service:   c.serviceName,
		Context:   fields,
		Error:     errorMsg,
	}

	jsonData, err := json.Marshal(entry)
	if err != nil {
		log.Printf("[%s] %s - %s (JSON marshal error: %v)",
			string(level), c.serviceName, message, err)
		return
	}

	fmt.Printf("%s\n", string(jsonData))
}

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
