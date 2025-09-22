package logging

import (
	"context"
	"fmt"
)

// DomainEventLogger provides logging for domain events
type DomainEventLogger struct {
	logger Logger
}

// NewDomainEventLogger creates a new domain event logger
func NewDomainEventLogger(logger Logger) *DomainEventLogger {
	return &DomainEventLogger{
		logger: logger.WithService("DomainEvents"),
	}
}

// LogRuleStateChange logs rule state transitions
func (d *DomainEventLogger) LogRuleStateChange(ctx context.Context, ruleID, oldState, newState string) {
	d.logger.Info(ctx, "Rule state changed", map[string]interface{}{
		"event_type": "rule_state_change",
		"rule_id":    ruleID,
		"old_state":  oldState,
		"new_state":  newState,
	})
}

// LogOfferStateChange logs offer state transitions
func (d *DomainEventLogger) LogOfferStateChange(ctx context.Context, offerID, oldState, newState string) {
	d.logger.Info(ctx, "Offer state changed", map[string]interface{}{
		"event_type": "offer_state_change",
		"offer_id":   offerID,
		"old_state":  oldState,
		"new_state":  newState,
	})
}

// LogOrderCreated logs order creation events
func (d *DomainEventLogger) LogOrderCreated(ctx context.Context, orderID, customerID string, amount float64) {
	d.logger.Info(ctx, "Order created", map[string]interface{}{
		"event_type":  "order_created",
		"order_id":    orderID,
		"customer_id": customerID,
		"amount":      amount,
	})
}

// LogPaymentProcessed logs payment processing events
func (d *DomainEventLogger) LogPaymentProcessed(ctx context.Context, paymentID, orderID, status string, amount float64) {
	d.logger.Info(ctx, "Payment processed", map[string]interface{}{
		"event_type": "payment_processed",
		"payment_id": paymentID,
		"order_id":   orderID,
		"status":     status,
		"amount":     amount,
	})
}

// LogError logs domain errors
func (d *DomainEventLogger) LogError(ctx context.Context, operation string, err error, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["operation"] = operation
	d.logger.Error(ctx, fmt.Sprintf("Domain error in %s", operation), err, fields)
}
