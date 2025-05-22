package infrastructure

import (
	"encoding/json"
	"fmt"
	"os"

	domainRepo "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/repository"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ses"
)

type SESNotifier struct {
	sesClient *ses.SES
	sender    string
}

func NewSESNotifier() (domainRepo.Notifier, error) {
	sender := os.Getenv("SES_SENDER_EMAIL")
	if sender == "" {
		return nil, fmt.Errorf("SES_SENDER_EMAIL environment variable is required")
	}

	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-2"),
	})
	if err != nil {
		return nil, fmt.Errorf("error creating AWS session: %w", err)
	}

	return &SESNotifier{
		sesClient: ses.New(sess),
		sender:    sender,
	}, nil
}

func (n *SESNotifier) SendEmail(email, subject, body string) error {
	input := &ses.SendEmailInput{
		Source: aws.String(n.sender),
		Destination: &ses.Destination{
			ToAddresses: aws.StringSlice([]string{email}),
		},
		Message: &ses.Message{
			Subject: &ses.Content{Data: aws.String(subject)},
			Body:    &ses.Body{Html: &ses.Content{Data: aws.String(body)}},
		},
	}

	_, err := n.sesClient.SendEmail(input)
	if err != nil {
		return fmt.Errorf("error sending email: %w", err)
	}

	return nil
}

func (n *SESNotifier) SendTemplatedEmail(email, templateName string, templateData map[string]string) error {
	jsonData, err := json.Marshal(templateData)
	if err != nil {
		return fmt.Errorf("error marshaling template data: %w", err)
	}

	input := &ses.SendTemplatedEmailInput{
		Source:       aws.String(n.sender),
		Template:     aws.String(templateName),
		TemplateData: aws.String(string(jsonData)),
		Destination: &ses.Destination{
			ToAddresses: aws.StringSlice([]string{email}),
		},
	}

	_, err = n.sesClient.SendTemplatedEmail(input)
	if err != nil {
		return fmt.Errorf("error sending templated email: %w", err)
	}

	return nil
}
