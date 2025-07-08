package scheduler

import (
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/eventbridge"
)

type AwsScheduler struct {
	eventBridge *eventbridge.EventBridge
}

func NewAwsScheduler(region string) (*AwsScheduler, error) {
	sess, err := session.NewSession(&aws.Config{Region: aws.String(region)})
	if err != nil {
		return nil, err
	}
	return &AwsScheduler{
		eventBridge: eventbridge.New(sess),
	}, nil
}

func (s *AwsScheduler) ScheduleLambda(scheduledTime time.Time, timeToSum time.Duration, targetArn, ruleName, payload string) error {
	execTime := scheduledTime.Add(timeToSum)
	scheduleStr := execTime.UTC().Format("2006-01-02T15:04:05Z")

	_, err := s.eventBridge.PutRule(&eventbridge.PutRuleInput{
		Name:               aws.String(ruleName),
		ScheduleExpression: aws.String(fmt.Sprintf("at(%s)", scheduleStr)),
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
				Id:    aws.String("1"),
				Input: aws.String(payload),
			},
		},
	})
	if err != nil {
		return fmt.Errorf("error asociando target Lambda: %w", err)
	}

	return nil
}
