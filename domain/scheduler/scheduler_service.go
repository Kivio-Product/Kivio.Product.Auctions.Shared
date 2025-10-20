package scheduler

import "time"

// SchedulerService defines the contract for scheduling operations
// 
// This interface abstracts scheduling operations, providing a clean contract
// for implementations that handle scheduling of AWS Lambda functions or other
// scheduled tasks. It supports scheduling with specific timing and duration
// parameters for automated task execution.
//
// Implementations should handle:
//   - AWS Lambda function scheduling
//   - EventBridge/CloudWatch Events rule creation
//   - Scheduled task management
//   - Error handling and retry logic
//   - Payload delivery to target functions
//
type SchedulerService interface {
	// ScheduleLambda schedules an AWS Lambda function to execute at a specific time
	// 
	// This method creates a scheduled execution for an AWS Lambda function using
	// EventBridge (CloudWatch Events) rules. It sets up the scheduling infrastructure
	// and configures the target Lambda function to receive the specified payload
	// at the scheduled time.
	//
	// Parameters:
	//   - scheduledTime: The exact time when the Lambda function should be executed
	//   - timeToSum: Duration to add to the scheduled time (for delayed execution)
	//   - targetArn: ARN of the target AWS Lambda function to invoke
	//   - ruleName: Unique name for the EventBridge rule
	//   - payload: JSON payload to pass to the Lambda function
	//
	// Returns:
	//   - error: Returns error if scheduling fails
	//
	// Side Effects:
	//   - Creates EventBridge rule for scheduled execution
	//   - Configures Lambda function as target
	//   - Sets up CloudWatch Events trigger
	//
	// Technical Details:
	//   - Uses AWS EventBridge for scheduling
	//   - Calculates execution time as scheduledTime + timeToSum
	//   - Creates unique rule name to avoid conflicts
	//   - Payload should be valid JSON string
	//   - Target ARN must be valid Lambda function ARN
	//   - Rule is automatically cleaned up after execution
	ScheduleLambda(scheduledTime time.Time, timeToSum time.Duration, targetArn, ruleName, payload string) error
}
