package logging

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/logging"
)

// LokiLogger implements the Logger interface using Grafana Loki
type LokiLogger struct {
	url         string
	username    string
	password    string
	serviceName string
	config      *LokiConfig
	httpClient  *http.Client
}

// LokiStream represents a Loki log stream
type LokiStream struct {
	Stream map[string]string `json:"stream"`
	Values [][]string        `json:"values"`
}

// LokiPushRequest represents a Loki push request
type LokiPushRequest struct {
	Streams []LokiStream `json:"streams"`
}

// NewLokiLogger creates a new Loki logger instance
func NewLokiLogger(config *LokiConfig) (*LokiLogger, error) {
	if !config.IsValid() {
		return nil, fmt.Errorf("invalid Loki configuration")
	}

	return &LokiLogger{
		url:         config.URL,
		username:    config.Username,
		password:    config.Password,
		serviceName: config.ServiceName,
		config:      config,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// Debug implements Logger.Debug
func (l *LokiLogger) Debug(ctx context.Context, message string, fields map[string]interface{}) {
	if !l.shouldLog(logging.DebugLevel) {
		return
	}
	l.log(ctx, logging.DebugLevel, message, "", fields)
}

// Info implements Logger.Info
func (l *LokiLogger) Info(ctx context.Context, message string, fields map[string]interface{}) {
	if !l.shouldLog(logging.InfoLevel) {
		return
	}
	l.log(ctx, logging.InfoLevel, message, "", fields)
}

// Warn implements Logger.Warn
func (l *LokiLogger) Warn(ctx context.Context, message string, fields map[string]interface{}) {
	if !l.shouldLog(logging.WarnLevel) {
		return
	}
	l.log(ctx, logging.WarnLevel, message, "", fields)
}

// Error implements Logger.Error
func (l *LokiLogger) Error(ctx context.Context, message string, err error, fields map[string]interface{}) {
	if !l.shouldLog(logging.ErrorLevel) {
		return
	}

	errorMsg := ""
	if err != nil {
		errorMsg = err.Error()
	}
	l.log(ctx, logging.ErrorLevel, message, errorMsg, fields)
}

// WithService implements Logger.WithService
func (l *LokiLogger) WithService(serviceName string) logging.Logger {
	return &LokiLogger{
		url:         l.url,
		username:    l.username,
		password:    l.password,
		serviceName: serviceName,
		config:      l.config,
		httpClient:  l.httpClient,
	}
}

// log sends a log entry to Loki
func (l *LokiLogger) log(ctx context.Context, level logging.LogLevel, message, errorMsg string, fields map[string]interface{}) {
	entry := logging.LogEntry{
		Level:     level,
		Message:   message,
		Timestamp: time.Now(),
		Service:   l.serviceName,
		Context:   fields,
		Error:     errorMsg,
	}

	// Convert to JSON
	jsonData, err := json.Marshal(entry)
	if err != nil {
		// Fallback to simple message if JSON marshaling fails
		jsonData = []byte(fmt.Sprintf(`{"level":"%s","message":"%s","service":"%s","timestamp":"%s"}`,
			level, message, l.serviceName, entry.Timestamp.Format(time.RFC3339)))
	}

	// Send to Loki asynchronously
	go l.sendToLoki(string(jsonData), entry.Timestamp, level)
}

// sendToLoki sends a log entry to Loki via HTTP
func (l *LokiLogger) sendToLoki(logLine string, timestamp time.Time, level logging.LogLevel) {
	// Create stream labels
	stream := map[string]string{
		"service":     l.serviceName,
		"level":       string(level),
		"environment": l.config.Environment,
	}

	// Create Loki push request
	pushRequest := LokiPushRequest{
		Streams: []LokiStream{
			{
				Stream: stream,
				Values: [][]string{
					{
						fmt.Sprintf("%d", timestamp.UnixNano()),
						logLine,
					},
				},
			},
		},
	}

	// Marshal request
	reqData, err := json.Marshal(pushRequest)
	if err != nil {
		fmt.Printf("Failed to marshal Loki request: %v\n", err)
		return
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", l.url, bytes.NewBuffer(reqData))
	if err != nil {
		fmt.Printf("Failed to create Loki request: %v\n", err)
		return
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	// Set basic authentication
	if l.username != "" && l.password != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(l.username + ":" + l.password))
		req.Header.Set("Authorization", "Basic "+auth)
	}

	// Send request with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := l.httpClient.Do(req)
	if err != nil {
		fmt.Printf("Failed to send log to Loki: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Printf("Loki returned error status: %d\n", resp.StatusCode)
	}
}

// shouldLog checks if the log level should be logged based on configuration
func (l *LokiLogger) shouldLog(level logging.LogLevel) bool {
	configLevel := l.config.LogLevel

	switch configLevel {
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
