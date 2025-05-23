package services

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	application "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/file_storage"
	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/repository"
)

type NotifyOfferUseCase struct {
	notifier           domain.Notifier
	fileStorageService application.IFileStorageService
}

func NewNotifyOfferUseCase(notifier domain.Notifier, fileStorageService application.IFileStorageService) *NotifyOfferUseCase {
	return &NotifyOfferUseCase{
		notifier:           notifier,
		fileStorageService: fileStorageService,
	}
}

func (uc *NotifyOfferUseCase) Execute(ctx context.Context, auctionURL string, offerName string) error {
	s3Key := os.Getenv("S3_EMAILS_FILE")
	if s3Key == "" {
		return fmt.Errorf("S3_EMAILS_FILE env variable is required")
	}

	content, err := uc.fileStorageService.ReadFile(ctx, s3Key)
	if err != nil {
		return err
	}

	emails := []string{}
	for _, line := range strings.Split(content, "\n") {
		email := strings.TrimSpace(line)
		if email != "" {
			emails = append(emails, email)
		}
	}

	expirationDate := time.Now().Add(24 * time.Hour).Format("02 de enero de 2006")

	for _, email := range emails {
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
