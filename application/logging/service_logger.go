package logging

import (
	"context"
	"time"

	"github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/logging"
)

type ServiceLogger struct {
	logger      logging.Logger
	serviceName string
}

func NewServiceLogger(loggerRepo logging.LoggerRepository, serviceName string) *ServiceLogger {
	return &ServiceLogger{
		logger:      loggerRepo.GetLogger().WithService(serviceName),
		serviceName: serviceName,
	}
}

func (s *ServiceLogger) LogServiceStart(ctx context.Context, operation string, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["operation"] = operation
	fields["phase"] = "start"

	s.logger.Info(ctx, "Service operation started", fields)
}

func (s *ServiceLogger) LogServiceEnd(ctx context.Context, operation string, duration time.Duration, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["operation"] = operation
	fields["phase"] = "end"
	fields["duration_ms"] = duration.Milliseconds()

	s.logger.Info(ctx, "Service operation completed", fields)
}

func (s *ServiceLogger) LogServiceError(ctx context.Context, operation string, err error, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["operation"] = operation
	fields["phase"] = "error"

	s.logger.Error(ctx, "Service operation failed", err, fields)
}

func (s *ServiceLogger) LogBusinessRule(ctx context.Context, ruleName string, result bool, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["rule_name"] = ruleName
	fields["rule_result"] = result
	fields["event_type"] = "business_rule_evaluation"

	s.logger.Info(ctx, "Business rule evaluated", fields)
}

func (s *ServiceLogger) LogExternalAPICall(ctx context.Context, apiName, endpoint string, duration time.Duration, success bool, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["api_name"] = apiName
	fields["endpoint"] = endpoint
	fields["duration_ms"] = duration.Milliseconds()
	fields["success"] = success
	fields["event_type"] = "external_api_call"

	if success {
		s.logger.Info(ctx, "External API call successful", fields)
	} else {
		s.logger.Warn(ctx, "External API call failed", fields)
	}
}

func (s *ServiceLogger) LogDatabaseOperation(ctx context.Context, operation, table string, duration time.Duration, success bool, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["db_operation"] = operation
	fields["db_table"] = table
	fields["duration_ms"] = duration.Milliseconds()
	fields["success"] = success
	fields["event_type"] = "database_operation"

	if success {
		s.logger.Debug(ctx, "Database operation completed", fields)
	} else {
		s.logger.Error(ctx, "Database operation failed", nil, fields)
	}
}

func (s *ServiceLogger) LogWorkflow(ctx context.Context, workflowName, step string, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["workflow_name"] = workflowName
	fields["workflow_step"] = step
	fields["event_type"] = "workflow_step"

	s.logger.Info(ctx, "Workflow step executed", fields)
}
