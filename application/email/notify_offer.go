package services

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	services "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/ecommerce"
	application "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/file_storage"
	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/repository"
)

type NotifyOfferUseCase struct {
	notifier                domain.Notifier
	fileStorageService      application.IFileStorageService
	ecommerceService        services.EcommerceService
	ecommerceCredentialsSvc services.EcommerceCredentialsService
}

func NewNotifyOfferUseCase(
	notifier domain.Notifier,
	fileStorageService application.IFileStorageService,
	ecommerceService services.EcommerceService,
	ecommerceCredentialsSvc services.EcommerceCredentialsService,
) *NotifyOfferUseCase {
	return &NotifyOfferUseCase{
		notifier:                notifier,
		fileStorageService:      fileStorageService,
		ecommerceService:        ecommerceService,
		ecommerceCredentialsSvc: ecommerceCredentialsSvc,
	}
}

func (uc *NotifyOfferUseCase) Execute(ctx context.Context, auctionURL, offerName, posID string) error {
	s3Key := os.Getenv("S3_EMAILS_FILE")
	if s3Key == "" {
		return fmt.Errorf("S3_EMAILS_FILE env variable is required")
	}
	content, err := uc.fileStorageService.ReadFile(ctx, s3Key)
	if err != nil {
		return err
	}
	emailSet := make(map[string]struct{})
	for _, line := range strings.Split(content, "\n") {
		email := strings.TrimSpace(line)
		if email != "" {
			emailSet[email] = struct{}{}
		}
	}

	credentials, err := uc.ecommerceCredentialsSvc.GetCredentials(ctx, posID)
	if err == nil {
		customers, err := uc.ecommerceService.GetCustomers(credentials.Context, credentials.ApiURL, credentials.ApiKey)
		if err == nil {
			for _, customer := range customers {
				email := strings.TrimSpace(customer.Email)
				if email != "" {
					emailSet[email] = struct{}{}
				}
			}
		}
	}

	expirationDate := time.Now().Add(24 * time.Hour).Format("02 de enero de 2006")
	for email := range emailSet {
		finalURL := addCustomerIdParam(auctionURL, email)
		templateData := map[string]string{
			"AUCTION_URL":       finalURL,
			"OFFER_DESCRIPTION": offerName,
			"EXPIRATION_DATE":   expirationDate,
		}
		err := uc.notifier.SendTemplatedEmail(email, "OfertaGeneral", templateData)
		if err != nil {
			fmt.Printf("Error enviando a %s: %v\n", email, err)
		}
	}
	return nil
}

func addCustomerIdParam(url, email string) string {
	sep := "?"
	if strings.Contains(url, "?") {
		sep = "&"
	}
	return url + sep + "customerId=" + email
}
