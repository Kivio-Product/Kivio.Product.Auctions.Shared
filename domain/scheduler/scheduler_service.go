package scheduler

import "time"

type SchedulerService interface {
	ScheduleLambda(scheduledTime time.Time, timeToSum time.Duration, targetArn, ruleName, payload string) error
}
