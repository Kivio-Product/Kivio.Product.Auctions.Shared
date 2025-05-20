package infrastructure

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	integrationInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/integration"
	s3Storage "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/s3"
)

type EmailSourceStrategy interface {
	GetEmails(ctx context.Context) ([]string, error)
}

type EcommerceEmailSourceStrategy interface {
	GetEmails(ctx context.Context, baseUrl, apiKey string) ([]string, error)
}

type S3EmailSource struct {
	fileStorage *s3Storage.S3FileStorage
	key         string
}

type EcommerceEmailSource struct {
	ecommerceRepo integrationInfrastructure.EcommerceRepository
}

func NewS3EmailSource() (EmailSourceStrategy, error) {
	bucket := os.Getenv("S3_BUCKET_NAME")
	key := os.Getenv("S3_EMAILS_FILE")

	if bucket == "" || key == "" {
		return nil, fmt.Errorf("faltan variables de entorno requeridas para S3EmailSource")
	}

	fileStorage, err := s3Storage.NewS3FileStorage(bucket)
	if err != nil {
		return nil, fmt.Errorf("error creating S3 file storage: %w", err)
	}

	return &S3EmailSource{
		fileStorage: fileStorage,
		key:         key,
	}, nil
}

func NewEcommerceEmailSource(ecommerceRepo integrationInfrastructure.EcommerceRepository) EcommerceEmailSourceStrategy {
	return &EcommerceEmailSource{
		ecommerceRepo: ecommerceRepo,
	}
}

func (s *S3EmailSource) GetEmails(ctx context.Context) ([]string, error) {
	lines, err := s.fileStorage.ReadFileLines(ctx, s.key)
	if err != nil {
		return nil, fmt.Errorf("error reading emails file: %w", err)
	}

	var emails []string
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

	for _, line := range lines {
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

	return emails, nil
}

func (e *EcommerceEmailSource) GetEmails(ctx context.Context, baseUrl, apiKey string) ([]string, error) {
	customers, err := e.ecommerceRepo.GetCustomers(baseUrl, apiKey)
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
