package logging

import (
	"context"
	"time"
)

// LogLevel represents the severity level of a log entry
type LogLevel string

const (
	DebugLevel LogLevel = "debug"
	InfoLevel  LogLevel = "info"
	WarnLevel  LogLevel = "warn"
	ErrorLevel LogLevel = "error"
)

// LogEntry represents a structured log entry
type LogEntry struct {
	Level     LogLevel               `json:"level"`
	Message   string                 `json:"message"`
	Timestamp time.Time              `json:"timestamp"`
	Service   string                 `json:"service"`
	Context   map[string]interface{} `json:"context,omitempty"`
	Error     string                 `json:"error,omitempty"`
}

// Logger defines the interface for logging operations
type Logger interface {
	Debug(ctx context.Context, message string, fields map[string]interface{})
	Info(ctx context.Context, message string, fields map[string]interface{})
	Warn(ctx context.Context, message string, fields map[string]interface{})
	Error(ctx context.Context, message string, err error, fields map[string]interface{})
	WithService(serviceName string) Logger
}

// LoggerRepository defines the interface for managing loggers
type LoggerRepository interface {
	GetLogger() Logger
	Close() error
}
