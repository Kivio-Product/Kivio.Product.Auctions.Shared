package infrastructure

import (
	"fmt"
	"log"
	"strings"

	domainRepo "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/repository"
)

type FallbackNotifier struct {
	primaryNotifier  domainRepo.Notifier
	fallbackNotifier domainRepo.Notifier
}

func NewFallbackNotifier(primary, fallback domainRepo.Notifier) domainRepo.Notifier {
	return &FallbackNotifier{
		primaryNotifier:  primary,
		fallbackNotifier: fallback,
	}
}

func (n *FallbackNotifier) SendEmail(email, subject, body string) error {
	err := n.primaryNotifier.SendEmail(email, subject, body)
	if err == nil {
		return nil
	}

	if isSESLimitError(err) {
		log.Printf("SES limit reached, falling back to SMTP for email: %s", email)

		fallbackErr := n.fallbackNotifier.SendEmail(email, subject, body)
		if fallbackErr != nil {
			return fmt.Errorf("both primary (SES) and fallback (SMTP) failed: SES error: %w, SMTP error: %w", err, fallbackErr)
		}

		log.Printf("Email sent successfully via SMTP fallback to: %s", email)
		return nil
	}

	return fmt.Errorf("primary notifier (SES) failed: %w", err)
}

func (n *FallbackNotifier) SendTemplatedEmail(email, templateName string, templateData map[string]string) error {
	err := n.primaryNotifier.SendTemplatedEmail(email, templateName, templateData)
	if err == nil {
		return nil
	}

	if isSESLimitError(err) {
		log.Printf("SES limit reached, falling back to SMTP for templated email: %s", email)

		fallbackErr := n.fallbackNotifier.SendTemplatedEmail(email, templateName, templateData)
		if fallbackErr != nil {
			return fmt.Errorf("both primary (SES) and fallback (SMTP) failed: SES error: %w, SMTP error: %w", err, fallbackErr)
		}

		log.Printf("Templated email sent successfully via SMTP fallback to: %s", email)
		return nil
	}

	return fmt.Errorf("primary notifier (SES) failed: %w", err)
}

func (n *FallbackNotifier) SendEmailWithAttachment(email, subject, body string, attachmentName string, attachmentData []byte) error {
	err := n.primaryNotifier.SendEmailWithAttachment(email, subject, body, attachmentName, attachmentData)
	if err == nil {
		return nil
	}

	if isSESLimitError(err) {
		log.Printf("SES limit reached, falling back to SMTP for email with attachment: %s", email)

		fallbackErr := n.fallbackNotifier.SendEmailWithAttachment(email, subject, body, attachmentName, attachmentData)
		if fallbackErr != nil {
			return fmt.Errorf("both primary (SES) and fallback (SMTP) failed: SES error: %w, SMTP error: %w", err, fallbackErr)
		}

		log.Printf("Email with attachment sent successfully via SMTP fallback to: %s", email)
		return nil
	}

	return fmt.Errorf("primary notifier (SES) failed: %w", err)
}

func isSESLimitError(err error) bool {
	if err == nil {
		return false
	}

	errMsg := strings.ToLower(err.Error())

	limitErrors := []string{
		"throttling",
		"quota exceeded",
		"daily sending quota",
		"maximum sending rate",
		"rate exceeded",
		"limit exceeded",
		"quota",
		"throttled",
	}

	for _, limitError := range limitErrors {
		if strings.Contains(errMsg, limitError) {
			return true
		}
	}

	return false
}
