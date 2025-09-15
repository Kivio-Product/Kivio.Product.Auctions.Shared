package logging

import "context"

type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
)

type Fields map[string]interface{}

type Logger interface {
	Debug(ctx context.Context, message string, fields Fields)
	Info(ctx context.Context, message string, fields Fields)
	Warn(ctx context.Context, message string, fields Fields)
	Error(ctx context.Context, message string, fields Fields)
	
	WithFields(fields Fields) Logger
	WithRequestID(requestID string) Logger
	WithUserID(userID string) Logger
	WithAuctionID(auctionID string) Logger
}

type Config struct {
	LokiURL      string
	ServiceName  string
	Environment  string
	LogLevel     LogLevel
	EnableConsole bool
}