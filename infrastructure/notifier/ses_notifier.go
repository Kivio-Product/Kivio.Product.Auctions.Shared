package infrastructure

import (
	"encoding/base64"
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

func (n *SESNotifier) SendEmailWithAttachment(email, subject, body string, attachmentName string, attachmentData []byte) error {
	boundary := "NextPartBoundary"

	headers := "From: " + n.sender + "\r\n" +
		"To: " + email + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=" + boundary + "\r\n\r\n"

	bodyPart := "--" + boundary + "\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: 7bit\r\n\r\n" +
		body + "\r\n\r\n"

	attachmentPart := "--" + boundary + "\r\n" +
		"Content-Type: application/pdf; name=\"" + attachmentName + "\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"Content-Disposition: attachment; filename=\"" + attachmentName + "\"\r\n\r\n"

	encodedAttachment := make([]byte, base64.StdEncoding.EncodedLen(len(attachmentData)))
	base64.StdEncoding.Encode(encodedAttachment, attachmentData)

	ending := "\r\n--" + boundary + "--"

	rawMessage := []byte(headers + bodyPart + attachmentPart + string(encodedAttachment) + ending)

	input := &ses.SendRawEmailInput{
		RawMessage: &ses.RawMessage{Data: rawMessage},
	}

	_, err := n.sesClient.SendRawEmail(input)
	if err != nil {
		return fmt.Errorf("error sending email with attachment: %w", err)
	}

	return nil
}
