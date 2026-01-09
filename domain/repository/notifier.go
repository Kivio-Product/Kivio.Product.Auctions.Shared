package domain

// Notifier defines the contract for notification operations
// 
// This interface abstracts notification operations, providing a clean contract
// for implementations that handle email sending, templated emails, and email
// attachments. It supports various email providers and notification services.
//
// Implementations should handle:
//   - Simple email sending with subject and body
//   - Templated email sending with dynamic data
//   - Email sending with file attachments
//   - Error handling and retry logic
//   - Email validation and formatting
//
type Notifier interface {
	// SendEmail sends a simple email with subject and body content
	// 
	// This method sends a basic email message with the provided subject and body.
	// It's suitable for simple notifications that don't require templating
	// or dynamic content.
	//
	// Parameters:
	//   - email: Recipient's email address
	//   - subject: Email subject line
	//   - body: Email body content (plain text or HTML)
	//
	// Returns:
	//   - error: Returns error if email sending fails
	//
	// Side Effects:
	//   - Sends email to recipient
	//   - May trigger email delivery events
	//
	// Technical Details:
	//   - Should validate email address format
	//   - Body can be plain text or HTML
	//   - Implementation should handle SMTP errors
	//   - Should include proper email headers
	SendEmail(email, subject, body string) error

	// SendTemplatedEmail sends an email using a predefined template with dynamic data
	// 
	// This method sends an email using a template system where placeholders
	// in the template are replaced with dynamic data. It's useful for
	// standardized email formats with personalized content.
	//
	// Parameters:
	//   - email: Recipient's email address
	//   - templateName: Name/identifier of the email template
	//   - templateData: Key-value pairs for template variable substitution
	//
	// Returns:
	//   - error: Returns error if email sending fails
	//
	// Side Effects:
	//   - Sends templated email to recipient
	//   - Processes template with provided data
	//
	// Technical Details:
	//   - Template should exist in template system
	//   - TemplateData keys should match template placeholders
	//   - Should handle missing template gracefully
	//   - Template processing should be secure (no code injection)
	SendTemplatedEmail(email, templateName string, templateData map[string]string) error

	// SendEmailWithAttachment sends an email with a file attachment
	// 
	// This method sends an email that includes a file attachment. It's useful
	// for sending documents, reports, or other files along with the email
	// message.
	//
	// Parameters:
	//   - email: Recipient's email address
	//   - subject: Email subject line
	//   - body: Email body content
	//   - attachmentName: Name of the attached file
	//   - attachmentData: Binary data of the file to attach
	//
	// Returns:
	//   - error: Returns error if email sending fails
	//
	// Side Effects:
	//   - Sends email with attachment to recipient
	//   - Processes attachment data
	//
	// Technical Details:
	//   - Attachment data should be valid binary content
	//   - AttachmentName should include proper file extension
	//   - Should handle large attachments appropriately
	//   - Email size limits may apply
	//   - Should use proper MIME types for attachments
	SendEmailWithAttachment(email, subject, body string, attachmentName string, attachmentData []byte) error
}
