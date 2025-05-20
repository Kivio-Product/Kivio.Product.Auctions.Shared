package infrastructure

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"

	itemDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item"
	itemSpecDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/item_specification"
	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/offer"
	orderDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/order"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/ses"
)

type IEmailSender interface {
	SendEmail(ctx context.Context, offer *domain.Offer, auctionURL string) error
	SendOrderEmail(ctx context.Context, order *orderDomain.Order, itemSpec *itemSpecDomain.ItemSpecification, item *itemDomain.Item, state string) error
}

type SESEmailSender struct {
	sesClient           *ses.SES
	s3Client            *s3.S3
	sender              string
	s3Bucket            string
	s3Key               string
	templateKey         string
	templateKeyApproved string
	templateKeyRejected string
	templateKeyQuick    string
	emailSource         EmailSourceStrategy
	ecommerceSource     EcommerceEmailSourceStrategy
}

func NewSESEmailSender(emailSource EmailSourceStrategy, ecommerceSource EcommerceEmailSourceStrategy) (IEmailSender, error) {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-2"),
	})
	if err != nil {
		return nil, fmt.Errorf("error creando sesión de AWS: %w", err)
	}

	sender := os.Getenv("SES_SENDER_EMAIL")
	bucket := os.Getenv("S3_BUCKET_NAME")
	s3Key := os.Getenv("S3_EMAILS_FILE")
	template := os.Getenv("S3_TEMPLATE_FILE")
	templateApproved := os.Getenv("S3_TEMPLATE_APPROVED")
	templateRejected := os.Getenv("S3_TEMPLATE_REJECTED")
	templateQuick := os.Getenv("S3_TEMPLATE_QUICK")

	if sender == "" || bucket == "" || s3Key == "" || template == "" {
		return nil, fmt.Errorf("faltan variables de entorno requeridas")
	}

	return &SESEmailSender{
		sesClient:           ses.New(sess),
		s3Client:            s3.New(sess),
		sender:              sender,
		s3Bucket:            bucket,
		s3Key:               s3Key,
		templateKey:         template,
		templateKeyApproved: templateApproved,
		templateKeyRejected: templateRejected,
		templateKeyQuick:    templateQuick,
		emailSource:         emailSource,
		ecommerceSource:     ecommerceSource,
	}, nil
}

func (s *SESEmailSender) readTemplateFromS3(ctx context.Context, key string) (string, error) {
	input := &s3.GetObjectInput{
		Bucket: aws.String(s.s3Bucket),
		Key:    aws.String(key),
	}

	result, err := s.s3Client.GetObjectWithContext(ctx, input)
	if err != nil {
		return "", fmt.Errorf("error al obtener la plantilla de S3: %w", err)
	}
	defer result.Body.Close()

	body, err := io.ReadAll(result.Body)
	if err != nil {
		return "", fmt.Errorf("error al leer la plantilla de S3: %w", err)
	}

	return string(body), nil
}

func replaceTemplateVars(template string, vars map[string]string) string {
	for key, value := range vars {
		template = strings.ReplaceAll(template, fmt.Sprintf("{{%s}}", key), value)
	}
	return template
}

func (s *SESEmailSender) SendEmail(ctx context.Context, offer *domain.Offer, auctionURL string) error {
	if s.sesClient == nil {
		return fmt.Errorf("SES client is not initialized")
	}

	var emails []string
	var err error

	if s.ecommerceSource != nil {
		baseUrl := os.Getenv("ECOMMERCE_BASE_URL")
		apiKey := os.Getenv("ECOMMERCE_API_KEY")
		emails, err = s.ecommerceSource.GetEmails(ctx, baseUrl, apiKey)
	} else {
		emails, err = s.emailSource.GetEmails(ctx)
	}

	if err != nil {
		return err
	}

	if len(emails) == 0 {
		return fmt.Errorf("no hay correos en la lista")
	}

	template, err := s.readTemplateFromS3(ctx, s.templateKey)
	if err != nil {
		return err
	}

	for _, email := range emails {
		personalizedURL := auctionURL + "&email=" + email

		vars := map[string]string{
			"OFFER_NAME":        offer.Name,
			"OFFER_DESCRIPTION": offer.Description,
			"DISCOUNT":          "50%",
			"AUCTION_TIME":      strconv.FormatInt(offer.AuctionTime, 10),
			"AUCTION_URL":       personalizedURL,
		}
		body := replaceTemplateVars(template, vars)

		subject := fmt.Sprintf("🔥 Oferta Especial: %s", offer.Name)

		input := &ses.SendEmailInput{
			Source: aws.String(s.sender),
			Destination: &ses.Destination{
				ToAddresses: aws.StringSlice([]string{email}),
			},
			Message: &ses.Message{
				Subject: &ses.Content{Data: aws.String(subject)},
				Body:    &ses.Body{Html: &ses.Content{Data: aws.String(body)}},
			},
		}

		_, err := s.sesClient.SendEmailWithContext(ctx, input)
		if err != nil {
			log.Printf("Error al enviar correo a %s: %v", email, err)
		} else {
			log.Printf("Correo enviado correctamente a %s", email)
		}
	}

	return nil
}

func (s *SESEmailSender) SendOrderEmail(ctx context.Context, order *orderDomain.Order, itemSpec *itemSpecDomain.ItemSpecification, item *itemDomain.Item, state string) error {
	if s.sesClient == nil {
		return fmt.Errorf("SES client is not initialized")
	}

	var templateKey string
	switch state {
	case "Approved":
		templateKey = s.templateKeyApproved
	case "Rejected":
		templateKey = s.templateKeyRejected
	case "Quick":
		templateKey = s.templateKeyQuick
	default:
		return fmt.Errorf("estado inválido: %s", state)
	}

	if templateKey == "" {
		return fmt.Errorf("no se configuró la plantilla para el estado %s", state)
	}

	template, err := s.readTemplateFromS3(ctx, templateKey)
	if err != nil {
		return err
	}

	vars := map[string]string{
		"ITEM_NAME":        item.Name,
		"ITEM_DESCRIPTION": item.Description,
		"AMOUNT":           strconv.FormatInt(order.OfferedAmount, 10),
	}
	body := replaceTemplateVars(template, vars)

	var subject string
	switch state {
	case "Approved":
		subject = fmt.Sprintf("🎉 ¡Felicidades! Has ganado la subasta de: %s", item.Name)
	case "Rejected":
		subject = fmt.Sprintf("Resultado de la subasta: %s", item.Name)
	case "Quick":
		subject = fmt.Sprintf("Oferta obtenida: %s", item.Name)
	}

	input := &ses.SendEmailInput{
		Source: aws.String(s.sender),
		Destination: &ses.Destination{
			ToAddresses: aws.StringSlice([]string{order.CustomerId}),
		},
		Message: &ses.Message{
			Subject: &ses.Content{Data: aws.String(subject)},
			Body:    &ses.Body{Html: &ses.Content{Data: aws.String(body)}},
		},
	}

	_, err = s.sesClient.SendEmailWithContext(ctx, input)
	if err != nil {
		log.Printf("Error al enviar correo a %s: %v", order.CustomerId, err)
	} else {
		log.Printf("Correo enviado correctamente a %s", order.CustomerId)
	}

	return nil
}
