package logging

import (
	"context"
	"time"

	domainLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/logging"
)

type InfrastructureLogger interface {
	LogDatabaseQuery(ctx context.Context, table string, operation string, duration time.Duration, success bool, fields domainLogging.Fields)
	LogExternalAPICall(ctx context.Context, service string, endpoint string, method string, statusCode int, duration time.Duration, fields domainLogging.Fields)
	LogFileOperation(ctx context.Context, operation string, filePath string, success bool, duration time.Duration, fields domainLogging.Fields)
	LogAWSServiceCall(ctx context.Context, service string, operation string, duration time.Duration, success bool, fields domainLogging.Fields)
	LogNotificationSent(ctx context.Context, channel string, recipient string, success bool, fields domainLogging.Fields)
}

type infrastructureLogger struct {
	logger domainLogging.Logger
}

func NewInfrastructureLogger(loggerRepo domainLogging.LoggerRepository, component string) InfrastructureLogger {
	return &infrastructureLogger{
		logger: loggerRepo.GetLogger().WithFields(domainLogging.Fields{
			"layer":     "infrastructure",
			"component": component,
		}),
	}
}

func (i *infrastructureLogger) LogDatabaseQuery(ctx context.Context, table string, operation string, duration time.Duration, success bool, fields domainLogging.Fields) {
	status := "success"
	if !success {
		status = "failure"
	}
	
	logFields := domainLogging.Fields{
		"table":       table,
		"operation":   operation,
		"duration_ms": duration.Milliseconds(),
		"status":      status,
		"db_type":     "dynamodb",
	}
	i.mergeFields(logFields, fields)
	
	level := i.logger.Info
	if !success {
		level = i.logger.Error
	}
	
	level(ctx, "Database operation", logFields)
}

func (i *infrastructureLogger) LogExternalAPICall(ctx context.Context, service string, endpoint string, method string, statusCode int, duration time.Duration, fields domainLogging.Fields) {
	success := statusCode >= 200 && statusCode < 300
	status := "success"
	if !success {
		status = "failure"
	}
	
	logFields := domainLogging.Fields{
		"external_service": service,
		"endpoint":         endpoint,
		"method":           method,
		"status_code":      statusCode,
		"duration_ms":      duration.Milliseconds(),
		"status":           status,
	}
	i.mergeFields(logFields, fields)
	
	level := i.logger.Info
	if !success {
		level = i.logger.Error
	}
	
	level(ctx, "External API call", logFields)
}

func (i *infrastructureLogger) LogFileOperation(ctx context.Context, operation string, filePath string, success bool, duration time.Duration, fields domainLogging.Fields) {
	status := "success"
	if !success {
		status = "failure"
	}
	
	logFields := domainLogging.Fields{
		"operation":   operation,
		"file_path":   filePath,
		"duration_ms": duration.Milliseconds(),
		"status":      status,
	}
	i.mergeFields(logFields, fields)
	
	level := i.logger.Info
	if !success {
		level = i.logger.Error
	}
	
	level(ctx, "File operation", logFields)
}

func (i *infrastructureLogger) LogAWSServiceCall(ctx context.Context, service string, operation string, duration time.Duration, success bool, fields domainLogging.Fields) {
	status := "success"
	if !success {
		status = "failure"
	}
	
	logFields := domainLogging.Fields{
		"aws_service": service,
		"operation":   operation,
		"duration_ms": duration.Milliseconds(),
		"status":      status,
	}
	i.mergeFields(logFields, fields)
	
	level := i.logger.Info
	if !success {
		level = i.logger.Error
	}
	
	level(ctx, "AWS service call", logFields)
}

func (i *infrastructureLogger) LogNotificationSent(ctx context.Context, channel string, recipient string, success bool, fields domainLogging.Fields) {
	status := "success"
	if !success {
		status = "failure"
	}
	
	logFields := domainLogging.Fields{
		"notification_channel": channel,
		"recipient":            recipient,
		"status":               status,
	}
	i.mergeFields(logFields, fields)
	
	level := i.logger.Info
	if !success {
		level = i.logger.Error
	}
	
	level(ctx, "Notification sent", logFields)
}

func (i *infrastructureLogger) mergeFields(target domainLogging.Fields, source domainLogging.Fields) {
	for k, v := range source {
		target[k] = v
	}
}