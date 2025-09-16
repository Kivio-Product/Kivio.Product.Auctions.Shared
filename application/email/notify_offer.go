package services

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	services "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/ecommerce"
	blackListService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/email_black_list"
	application "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/file_storage"
	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/repository"
)

type NotifyOfferUseCase struct {
	notifier                domain.Notifier
	fileStorageService      application.IFileStorageService
	ecommerceService        services.EcommerceService
	ecommerceCredentialsSvc services.EcommerceCredentialsService
	emailBlackListService   blackListService.EmailBlackListService
}

func NewNotifyOfferUseCase(
	notifier domain.Notifier,
	fileStorageService application.IFileStorageService,
	ecommerceService services.EcommerceService,
	ecommerceCredentialsSvc services.EcommerceCredentialsService,
	emailBlackListService blackListService.EmailBlackListService,
) *NotifyOfferUseCase {
	return &NotifyOfferUseCase{
		notifier:                notifier,
		fileStorageService:      fileStorageService,
		ecommerceService:        ecommerceService,
		ecommerceCredentialsSvc: ecommerceCredentialsSvc,
		emailBlackListService:   emailBlackListService,
	}
}

func (uc *NotifyOfferUseCase) Execute(ctx context.Context, auctionURL, unsubscribeUrl, offerName, posID, posName string) error {
	retrieveS3Emails := os.Getenv("SHOULD_RETRIEVE_S3_EMAILS")
	emailSet := make(map[string]struct{})

	if retrieveS3Emails == "true" {
		s3Key := os.Getenv("S3_EMAILS_FILE")
		if s3Key == "" {
			return fmt.Errorf("S3_EMAILS_FILE env variable is required")
		}
		content, err := uc.fileStorageService.ReadFile(ctx, s3Key)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(content, "\n") {
			email := strings.TrimSpace(line)
			if email != "" {
				emailSet[email] = struct{}{}
			}
		}
	} else {
		credentials, err := uc.ecommerceCredentialsSvc.GetCredentials(ctx, posID)
		if err == nil {
			customers, err := uc.ecommerceService.GetCustomers(credentials.Context, credentials.ApiURL, credentials.ApiKey)
			if err == nil {
				blackListEmails, err := uc.emailBlackListService.GetBlackListEmails()
				if err != nil {
					log.Printf("error al obtener emails desde dynamo: %v", err)
				}
				for _, customer := range customers {
					email := strings.TrimSpace(customer.Email)
					fmt.Print("EMAIL", email)
					if email != "" {
						if _, exists := blackListEmails[email]; !exists {
							emailSet[email] = struct{}{}
						}
					}
				}
			}
		}
	}

	expirationDate := time.Now().Add(24 * time.Hour).Format("02 de enero de 2006")
	for email := range emailSet {
		finalURL := addCustomerIdParam(auctionURL, email)
		finalUnsubscribeUrl := addCustomerIdParam(unsubscribeUrl, email)
		templateData := map[string]string{
			"AUCTION_URL":       finalURL,
			"OFFER_DESCRIPTION": offerName,
			"EXPIRATION_DATE":   expirationDate,
			"UNSUBSCRIBE_URL":   finalUnsubscribeUrl,
		}

		templateName := "OfertaGeneral"

		if posName != "" {
			templateName = templateName + posName
		}

		err := uc.notifier.SendTemplatedEmail(email, templateName, templateData)
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
