package logging

import (
	"context"
	"time"
)

type DomainEvent struct {
	EventType   string
	AggregateID string
	Timestamp   time.Time
	Data        Fields
}

type DomainEventLogger interface {
	LogRuleStateChange(ctx context.Context, ruleID string, oldState string, newState string)
	LogOfferCreated(ctx context.Context, offerID string, userID string, amount float64)
	LogOrderCreated(ctx context.Context, orderID string, userID string, totalAmount float64)
	LogItemCreated(ctx context.Context, itemID string, externalID string)
	LogBillingProcessed(ctx context.Context, billingID string, orderID string, status string)
	LogIntegrationEvent(ctx context.Context, eventType string, externalSystem string, data Fields)
}

func NewDomainEventLogger(logger Logger) DomainEventLogger {
	return &domainEventLogger{
		logger: logger.WithFields(Fields{"component": "domain_events"}),
	}
}

type domainEventLogger struct {
	logger Logger
}

func (d *domainEventLogger) LogRuleStateChange(ctx context.Context, ruleID string, oldState string, newState string) {
	d.logger.Info(ctx, "Rule state changed", Fields{
		"rule_id":    ruleID,
		"old_state":  oldState,
		"new_state":  newState,
		"event_type": "rule_state_change",
	})
}

func (d *domainEventLogger) LogOfferCreated(ctx context.Context, offerID string, userID string, amount float64) {
	d.logger.Info(ctx, "Offer created", Fields{
		"offer_id":   offerID,
		"user_id":    userID,
		"amount":     amount,
		"event_type": "offer_created",
	})
}

func (d *domainEventLogger) LogOrderCreated(ctx context.Context, orderID string, userID string, totalAmount float64) {
	d.logger.Info(ctx, "Order created", Fields{
		"order_id":     orderID,
		"user_id":      userID,
		"total_amount": totalAmount,
		"event_type":   "order_created",
	})
}

func (d *domainEventLogger) LogItemCreated(ctx context.Context, itemID string, externalID string) {
	d.logger.Info(ctx, "Item created", Fields{
		"item_id":     itemID,
		"external_id": externalID,
		"event_type":  "item_created",
	})
}

func (d *domainEventLogger) LogBillingProcessed(ctx context.Context, billingID string, orderID string, status string) {
	d.logger.Info(ctx, "Billing processed", Fields{
		"billing_id": billingID,
		"order_id":   orderID,
		"status":     status,
		"event_type": "billing_processed",
	})
}

func (d *domainEventLogger) LogIntegrationEvent(ctx context.Context, eventType string, externalSystem string, data Fields) {
	logData := Fields{
		"event_type":      eventType,
		"external_system": externalSystem,
	}

	for k, v := range data {
		logData[k] = v
	}

	d.logger.Info(ctx, "Integration event", logData)
}
