package logging

import (
	"context"
	"time"

	"github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/logging"
)

// InfrastructureLogger provides logging utilities for infrastructure layer
type InfrastructureLogger struct {
	logger        logging.Logger
	componentName string
}

// NewInfrastructureLogger creates a new infrastructure logger
func NewInfrastructureLogger(loggerRepo logging.LoggerRepository, componentName string) *InfrastructureLogger {
	serviceName := "Infrastructure-" + componentName
	return &InfrastructureLogger{
		logger:        loggerRepo.GetLogger().WithService(serviceName),
		componentName: componentName,
	}
}

// LogDatabaseQuery logs database query operations
func (i *InfrastructureLogger) LogDatabaseQuery(ctx context.Context, table, operation string, duration time.Duration, success bool, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["component"] = i.componentName
	fields["table"] = table
	fields["operation"] = operation
	fields["duration_ms"] = duration.Milliseconds()
	fields["success"] = success
	fields["event_type"] = "database_query"

	message := "Database query executed"
	if success {
		i.logger.Debug(ctx, message, fields)
	} else {
		i.logger.Error(ctx, "Database query failed", nil, fields)
	}
}

// LogS3Operation logs S3 file operations
func (i *InfrastructureLogger) LogS3Operation(ctx context.Context, operation, bucket, key string, duration time.Duration, success bool, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["component"] = i.componentName
	fields["operation"] = operation
	fields["bucket"] = bucket
	fields["key"] = key
	fields["duration_ms"] = duration.Milliseconds()
	fields["success"] = success
	fields["event_type"] = "s3_operation"

	message := "S3 operation executed"
	if success {
		i.logger.Info(ctx, message, fields)
	} else {
		i.logger.Error(ctx, "S3 operation failed", nil, fields)
	}
}

// LogEmailSent logs email sending operations
func (i *InfrastructureLogger) LogEmailSent(ctx context.Context, provider, recipient string, success bool, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["component"] = i.componentName
	fields["email_provider"] = provider
	fields["recipient"] = recipient
	fields["success"] = success
	fields["event_type"] = "email_sent"

	message := "Email sent"
	if success {
		i.logger.Info(ctx, message, fields)
	} else {
		i.logger.Error(ctx, "Email sending failed", nil, fields)
	}
}

// LogHTTPRequest logs HTTP requests to external services
func (i *InfrastructureLogger) LogHTTPRequest(ctx context.Context, method, url string, statusCode int, duration time.Duration, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["component"] = i.componentName
	fields["http_method"] = method
	fields["url"] = url
	fields["status_code"] = statusCode
	fields["duration_ms"] = duration.Milliseconds()
	fields["event_type"] = "http_request"

	message := "HTTP request completed"
	if statusCode >= 200 && statusCode < 300 {
		i.logger.Info(ctx, message, fields)
	} else if statusCode >= 400 {
		i.logger.Warn(ctx, "HTTP request returned error status", fields)
	} else {
		i.logger.Debug(ctx, message, fields)
	}
}

// LogConnectionEvent logs connection events (database, external services)
func (i *InfrastructureLogger) LogConnectionEvent(ctx context.Context, service string, event string, success bool, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["component"] = i.componentName
	fields["service"] = service
	fields["connection_event"] = event
	fields["success"] = success
	fields["event_type"] = "connection_event"

	message := "Connection event"
	if success {
		i.logger.Info(ctx, message, fields)
	} else {
		i.logger.Error(ctx, "Connection event failed", nil, fields)
	}
}
