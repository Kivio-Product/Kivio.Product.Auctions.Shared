package domain

// EmailBlackList represents an email address that is blocked from the system
// 
// This entity is used to maintain a list of email addresses that should be
// prevented from participating in auctions, receiving notifications, or
// performing other system operations. It serves as a simple blocking mechanism
// for email-based access control.
type EmailBlackList struct {
	Email string
}
