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

type LokiLogger struct {
	url         string
	username    string
	password    string
	serviceName string
	config      *LokiConfig
	httpClient  *http.Client
}

type LokiStream struct {
	Stream map[string]string `json:"stream"`
	Values [][]string        `json:"values"`
}

type LokiPushRequest struct {
	Streams []LokiStream `json:"streams"`
}

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

func (l *LokiLogger) Debug(ctx context.Context, message string, fields map[string]interface{}) {
	if !l.shouldLog(logging.DebugLevel) {
		return
	}
	l.log(ctx, logging.DebugLevel, message, "", fields)
}

func (l *LokiLogger) Info(ctx context.Context, message string, fields map[string]interface{}) {
	if !l.shouldLog(logging.InfoLevel) {
		return
	}
	l.log(ctx, logging.InfoLevel, message, "", fields)
}

func (l *LokiLogger) Warn(ctx context.Context, message string, fields map[string]interface{}) {
	if !l.shouldLog(logging.WarnLevel) {
		return
	}
	l.log(ctx, logging.WarnLevel, message, "", fields)
}

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

func (l *LokiLogger) log(ctx context.Context, level logging.LogLevel, message, errorMsg string, fields map[string]interface{}) {
	entry := logging.LogEntry{
		Level:     level,
		Message:   message,
		Timestamp: time.Now(),
		Service:   l.serviceName,
		Context:   fields,
		Error:     errorMsg,
	}

	jsonData, err := json.Marshal(entry)
	if err != nil {
		jsonData = []byte(fmt.Sprintf(`{"level":"%s","message":"%s","service":"%s","timestamp":"%s"}`,
			level, message, l.serviceName, entry.Timestamp.Format(time.RFC3339)))
	}

	go l.sendToLoki(string(jsonData), entry.Timestamp, level)
}

func (l *LokiLogger) sendToLoki(logLine string, timestamp time.Time, level logging.LogLevel) {
	stream := map[string]string{
		"service":     l.serviceName,
		"level":       string(level),
		"environment": l.config.Environment,
	}

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

	reqData, err := json.Marshal(pushRequest)
	if err != nil {
		fmt.Printf("Failed to marshal Loki request: %v\n", err)
		return
	}

	req, err := http.NewRequest("POST", l.url, bytes.NewBuffer(reqData))
	if err != nil {
		fmt.Printf("Failed to create Loki request: %v\n", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")

	if l.username != "" && l.password != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(l.username + ":" + l.password))
		req.Header.Set("Authorization", "Basic "+auth)
	}

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
