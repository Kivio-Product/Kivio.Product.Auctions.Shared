package logging

import (
	"context"
	"time"

	domainLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/logging"
)

type ServiceLogger interface {
	LogServiceStart(ctx context.Context, serviceName string, operation string, fields domainLogging.Fields)
	LogServiceSuccess(ctx context.Context, serviceName string, operation string, duration time.Duration, fields domainLogging.Fields)
	LogServiceError(ctx context.Context, serviceName string, operation string, err error, duration time.Duration, fields domainLogging.Fields)
	LogBusinessEvent(ctx context.Context, eventType string, fields domainLogging.Fields)
	LogExternalCall(ctx context.Context, system string, operation string, duration time.Duration, success bool, fields domainLogging.Fields)
	LogDataOperation(ctx context.Context, operation string, table string, recordID string, success bool, fields domainLogging.Fields)
}

type serviceLogger struct {
	logger domainLogging.Logger
}

func NewServiceLogger(loggerRepo domainLogging.LoggerRepository, serviceName string) ServiceLogger {
	return &serviceLogger{
		logger: loggerRepo.GetLogger().WithFields(domainLogging.Fields{
			"layer":   "application",
			"service": serviceName,
		}),
	}
}

func (s *serviceLogger) LogServiceStart(ctx context.Context, serviceName string, operation string, fields domainLogging.Fields) {
	logFields := domainLogging.Fields{
		"operation": operation,
	}
	s.mergeFields(logFields, fields)
	
	s.logger.Info(ctx, "Service operation started", logFields)
}

func (s *serviceLogger) LogServiceSuccess(ctx context.Context, serviceName string, operation string, duration time.Duration, fields domainLogging.Fields) {
	logFields := domainLogging.Fields{
		"operation":   operation,
		"duration_ms": duration.Milliseconds(),
		"status":      "success",
	}
	s.mergeFields(logFields, fields)
	
	s.logger.Info(ctx, "Service operation completed successfully", logFields)
}

func (s *serviceLogger) LogServiceError(ctx context.Context, serviceName string, operation string, err error, duration time.Duration, fields domainLogging.Fields) {
	logFields := domainLogging.Fields{
		"operation":   operation,
		"duration_ms": duration.Milliseconds(),
		"status":      "error",
		"error":       err.Error(),
	}
	s.mergeFields(logFields, fields)
	
	s.logger.Error(ctx, "Service operation failed", logFields)
}

func (s *serviceLogger) LogBusinessEvent(ctx context.Context, eventType string, fields domainLogging.Fields) {
	logFields := domainLogging.Fields{
		"event_type":  eventType,
		"event_layer": "business",
	}
	s.mergeFields(logFields, fields)
	
	s.logger.Info(ctx, "Business event occurred", logFields)
}

func (s *serviceLogger) LogExternalCall(ctx context.Context, system string, operation string, duration time.Duration, success bool, fields domainLogging.Fields) {
	status := "success"
	if !success {
		status = "failure"
	}
	
	logFields := domainLogging.Fields{
		"external_system": system,
		"operation":       operation,
		"duration_ms":     duration.Milliseconds(),
		"status":          status,
	}
	s.mergeFields(logFields, fields)
	
	level := s.logger.Info
	if !success {
		level = s.logger.Error
	}
	
	level(ctx, "External system call", logFields)
}

func (s *serviceLogger) LogDataOperation(ctx context.Context, operation string, table string, recordID string, success bool, fields domainLogging.Fields) {
	status := "success"
	if !success {
		status = "failure"
	}
	
	logFields := domainLogging.Fields{
		"operation": operation,
		"table":     table,
		"record_id": recordID,
		"status":    status,
		"layer":     "data",
	}
	s.mergeFields(logFields, fields)
	
	level := s.logger.Info
	if !success {
		level = s.logger.Error
	}
	
	level(ctx, "Data operation", logFields)
}

func (s *serviceLogger) mergeFields(target domainLogging.Fields, source domainLogging.Fields) {
	for k, v := range source {
		target[k] = v
	}
}