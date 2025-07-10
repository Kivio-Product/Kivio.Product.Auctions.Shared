package scheduler

import (
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/eventbridge"
	"github.com/google/uuid"
)

type AwsScheduler struct {
	eventBridge *eventbridge.EventBridge
}

func NewAwsScheduler() (*AwsScheduler, error) {
	sess, err := session.NewSession(&aws.Config{Region: aws.String("us-east-1")})
	if err != nil {
		return nil, err
	}
	return &AwsScheduler{
		eventBridge: eventbridge.New(sess),
	}, nil
}

func (s *AwsScheduler) ScheduleLambda(scheduledTime time.Time, timeToSum time.Duration, targetArn, ruleName, payload string) error {

	execTime := scheduledTime.Add(timeToSum).UTC()

	cronExpr := fmt.Sprintf(
		"cron(%d %d %d %d ? %d)",
		execTime.Minute(),
		execTime.Hour(),
		execTime.Day(),
		int(execTime.Month()),
		execTime.Year(),
	)

	fmt.Printf("Scheduling Lambda at %s with payload: %s\n", execTime.Format(time.RFC3339), payload)
	fmt.Printf("Using cron expression: %s\n", cronExpr)

	_, err := s.eventBridge.PutRule(&eventbridge.PutRuleInput{
		Name:               aws.String(ruleName),
		ScheduleExpression: aws.String(cronExpr),
		State:              aws.String("ENABLED"),
	})
	if err != nil {
		return fmt.Errorf("error creando regla EventBridge: %w", err)
	}

	_, err = s.eventBridge.PutTargets(&eventbridge.PutTargetsInput{
		Rule: aws.String(ruleName),
		Targets: []*eventbridge.Target{
			{
				Arn:   aws.String(targetArn),
				Id:    aws.String("target-" + uuid.New().String()),
				Input: aws.String(payload),
			},
		},
	})
	if err != nil {
		return fmt.Errorf("error asociando target Lambda: %w", err)
	}

	return nil
}
