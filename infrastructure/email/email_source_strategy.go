package infrastructure

import (
	"bufio"
	"context"
	"fmt"
	"regexp"
	"strings"

	integrationInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/integration"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
)

type EmailSourceStrategy interface {
	GetEmails(ctx context.Context) ([]string, error)
}

type S3EmailSource struct {
	s3Client *s3.S3
	bucket   string
	key      string
}

type EcommerceEmailSource struct {
	ecommerceRepo integrationInfrastructure.EcommerceRepository
	baseUrl       string
	apiKey        string
}

func NewS3EmailSource(s3Client *s3.S3, bucket, key string) EmailSourceStrategy {
	return &S3EmailSource{
		s3Client: s3Client,
		bucket:   bucket,
		key:      key,
	}
}

func NewEcommerceEmailSource(ecommerceRepo integrationInfrastructure.EcommerceRepository, baseUrl, apiKey string) EmailSourceStrategy {
	return &EcommerceEmailSource{
		ecommerceRepo: ecommerceRepo,
		baseUrl:       baseUrl,
		apiKey:        apiKey,
	}
}

func (s *S3EmailSource) GetEmails(ctx context.Context) ([]string, error) {
	input := &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.key),
	}

	result, err := s.s3Client.GetObjectWithContext(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("error al obtener el archivo de S3: %w", err)
	}
	defer result.Body.Close()

	scanner := bufio.NewScanner(result.Body)
	var emails []string
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

	for scanner.Scan() {
		line := scanner.Text()
		possibleEmails := strings.FieldsFunc(line, func(r rune) bool {
			return r == ';' || r == ',' || r == ' ' || r == '\t'
		})

		for _, email := range possibleEmails {
			cleaned := strings.TrimSpace(email)
			if emailRegex.MatchString(cleaned) {
				emails = append(emails, cleaned)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error al leer el archivo de S3: %w", err)
	}

	return emails, nil
}

func (e *EcommerceEmailSource) GetEmails(ctx context.Context) ([]string, error) {
	customers, err := e.ecommerceRepo.GetCustomers(e.baseUrl, e.apiKey)
	if err != nil {
		return nil, fmt.Errorf("error al obtener clientes del ecommerce: %w", err)
	}

	var emails []string
	for _, customer := range customers {
		if customer.Email != "" {
			emails = append(emails, customer.Email)
		}
	}

	return emails, nil
}
