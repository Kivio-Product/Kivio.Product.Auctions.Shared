package infrastructure

import (
	"fmt"
	"log"
	"os"

	domainRepo "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/repository"
)

func NewNotifierWithFallback() (domainRepo.Notifier, error) {
	sesNotifier, err := NewSESNotifier()
	if err != nil {
		log.Printf("Warning: Could not create SES notifier: %v", err)
		return createSMTPNotifier()
	}

	useSMTP := os.Getenv("USE_SMTP_FALLBACK")
	if useSMTP == "true" || useSMTP == "1" {
		smtpNotifier, err := createSMTPNotifier()
		if err != nil {
			log.Printf("Warning: Could not create SMTP notifier: %v", err)
			log.Printf("Using SES only without fallback")
			return sesNotifier, nil
		}

		log.Printf("Creating notifier with SES primary and SMTP fallback")
		return NewFallbackNotifier(sesNotifier, smtpNotifier), nil
	}

	log.Printf("Using SES notifier only")
	return sesNotifier, nil
}

func createSMTPNotifier() (domainRepo.Notifier, error) {
	username := os.Getenv("SMTP_USERNAME")
	password := os.Getenv("SMTP_PASSWORD")

	if username == "" || password == "" {
		return nil, fmt.Errorf("SMTP_USERNAME and SMTP_PASSWORD environment variables are required for SMTP fallback")
	}

	smtpNotifier, err := NewSMTPNotifier()
	if err != nil {
		return nil, fmt.Errorf("failed to create SMTP notifier: %w", err)
	}

	return smtpNotifier, nil
}

func NewNotifierFromConfig() (domainRepo.Notifier, error) {
	emailProvider := os.Getenv("EMAIL_PROVIDER")

	switch emailProvider {
	case "ses":
		return NewSESNotifier()
	case "smtp":
		return createSMTPNotifier()
	case "fallback", "":
		return NewNotifierWithFallback()
	default:
		return nil, fmt.Errorf("unsupported email provider: %s. Use 'ses', 'smtp', or 'fallback'", emailProvider)
	}
}
