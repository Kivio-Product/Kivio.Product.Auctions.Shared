package logging

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/grafana/loki-client-go/loki"
	"github.com/sirupsen/logrus"

	domainLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/logging"
)

type LokiLogger struct {
	lokiClient *loki.Client
	logrus     *logrus.Logger
	config     domainLogging.Config
	baseFields domainLogging.Fields
}

func NewLokiLogger(config domainLogging.Config) (*LokiLogger, error) {
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339,
	})

	if config.EnableConsole {
		logger.SetOutput(os.Stdout)
	}

	switch config.LogLevel {
	case domainLogging.DEBUG:
		logger.SetLevel(logrus.DebugLevel)
	case domainLogging.INFO:
		logger.SetLevel(logrus.InfoLevel)
	case domainLogging.WARN:
		logger.SetLevel(logrus.WarnLevel)
	case domainLogging.ERROR:
		logger.SetLevel(logrus.ErrorLevel)
	default:
		logger.SetLevel(logrus.InfoLevel)
	}

	var lokiClient *loki.Client
	if config.LokiURL != "" {
		cfg, err := loki.NewDefaultConfig(config.LokiURL)
		if err != nil {
			return nil, fmt.Errorf("failed to create loki config: %w", err)
		}

		cfg.TenantID = ""

		lokiClient, err = loki.New(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create loki client: %w", err)
		}
	}

	return &LokiLogger{
		lokiClient: lokiClient,
		logrus:     logger,
		config:     config,
		baseFields: domainLogging.Fields{
			"service":     config.ServiceName,
			"environment": config.Environment,
		},
	}, nil
}

func (l *LokiLogger) Debug(ctx context.Context, message string, fields domainLogging.Fields) {
	l.log(ctx, domainLogging.DEBUG, message, fields)
}

func (l *LokiLogger) Info(ctx context.Context, message string, fields domainLogging.Fields) {
	l.log(ctx, domainLogging.INFO, message, fields)
}

func (l *LokiLogger) Warn(ctx context.Context, message string, fields domainLogging.Fields) {
	l.log(ctx, domainLogging.WARN, message, fields)
}

func (l *LokiLogger) Error(ctx context.Context, message string, fields domainLogging.Fields) {
	l.log(ctx, domainLogging.ERROR, message, fields)
}

func (l *LokiLogger) WithFields(fields domainLogging.Fields) domainLogging.Logger {
	newFields := make(domainLogging.Fields)

	for k, v := range l.baseFields {
		newFields[k] = v
	}

	for k, v := range fields {
		newFields[k] = v
	}

	return &LokiLogger{
		lokiClient: l.lokiClient,
		logrus:     l.logrus,
		config:     l.config,
		baseFields: newFields,
	}
}

func (l *LokiLogger) WithRequestID(requestID string) domainLogging.Logger {
	return l.WithFields(domainLogging.Fields{"request_id": requestID})
}

func (l *LokiLogger) WithUserID(userID string) domainLogging.Logger {
	return l.WithFields(domainLogging.Fields{"user_id": userID})
}

func (l *LokiLogger) WithAuctionID(auctionID string) domainLogging.Logger {
	return l.WithFields(domainLogging.Fields{"auction_id": auctionID})
}

func (l *LokiLogger) log(ctx context.Context, level domainLogging.LogLevel, message string, fields domainLogging.Fields) {
	allFields := make(logrus.Fields)
	for k, v := range l.baseFields {
		allFields[k] = v
	}
	for k, v := range fields {
		allFields[k] = v
	}

	if requestID := ctx.Value("request_id"); requestID != nil {
		allFields["request_id"] = requestID
	}
	if userID := ctx.Value("user_id"); userID != nil {
		allFields["user_id"] = userID
	}

	entry := l.logrus.WithFields(allFields)
	switch level {
	case domainLogging.DEBUG:
		entry.Debug(message)
	case domainLogging.INFO:
		entry.Info(message)
	case domainLogging.WARN:
		entry.Warn(message)
	case domainLogging.ERROR:
		entry.Error(message)
	}

	if l.lokiClient != nil {
		entry.WithField("loki_enabled", true).Debug("Log would be sent to Loki")
	}
}

func (l *LokiLogger) levelString(level domainLogging.LogLevel) string {
	switch level {
	case domainLogging.DEBUG:
		return "debug"
	case domainLogging.INFO:
		return "info"
	case domainLogging.WARN:
		return "warn"
	case domainLogging.ERROR:
		return "error"
	default:
		return "info"
	}
}

func (l *LokiLogger) formatLogLine(message string, fields logrus.Fields) string {
	if len(fields) == 0 {
		return message
	}

	logData := map[string]interface{}{
		"message": message,
		"fields":  fields,
	}

	return fmt.Sprintf("%s %+v", message, logData)
}

func (l *LokiLogger) Close() error {
	if l.lokiClient != nil {
		l.lokiClient.Stop()
	}
	return nil
}
