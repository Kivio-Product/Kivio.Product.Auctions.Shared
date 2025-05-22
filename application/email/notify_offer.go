package services

import (
	"context"
	"fmt"
	"os"
	"strings"

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

	for _, email := range emails {
		templateData := map[string]string{
			"AUCTION_URL":       auctionURL,
			"OFFER_DESCRIPTION": offerName,
			"DISCOUNT":          "20%",
			"EXPIRATION_DATE":   "31 de diciembre de 2025",
		}
		err := uc.notifier.SendTemplatedEmail(email, "OfertaGeneral", templateData)
		if err != nil {
			fmt.Printf("Error enviando a %s: %v\n", email, err)
		}
	}

	return nil
}
