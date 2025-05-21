package domain

type Notifier interface {
	SendEmail(email, subject, body string) error
	SendTemplatedEmail(email, templateName string, templateData map[string]string) error
}
