package services

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/dto"
	services "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/ecommerce"
	application "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/file_storage"
	service "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/integration"
	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/repository"
)

type NotifyOfferUseCase struct {
	notifier           domain.Notifier
	fileStorageService application.IFileStorageService
	integrationService service.IntegrationService
	ecommerceService   services.EcommerceService
}

func NewNotifyOfferUseCase(
	notifier domain.Notifier,
	fileStorageService application.IFileStorageService,
	integrationService service.IntegrationService,
	ecommerceService services.EcommerceService,
) *NotifyOfferUseCase {
	return &NotifyOfferUseCase{
		notifier:           notifier,
		fileStorageService: fileStorageService,
		integrationService: integrationService,
		ecommerceService:   ecommerceService,
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

	integrations, err := uc.integrationService.GetIntegrationsByPosID(ctx, posID)
	if err == nil {
		var ecommerceIntegration *dto.IntegrationResponse
		for _, integ := range integrations {
			if integ.Type == "kivio_ecommerce" && integ.Status == "Active" {
				ecommerceIntegration = integ
				break
			}
		}
		if ecommerceIntegration != nil {
			var apiUrl, username, password string
			for _, cfg := range ecommerceIntegration.Configs {
				switch cfg.Key {
				case "apiUrl":
					apiUrl = cfg.Value
				case "username":
					username = cfg.Value
				case "password":
					password = cfg.Value
				}
			}
			if apiUrl != "" && username != "" && password != "" {
				tokenUrl := fmt.Sprintf("%s/token", apiUrl)
				apiKey, err := uc.ecommerceService.GetApiKey(ctx, username, password, tokenUrl)
				if err == nil {
					customers, err := uc.ecommerceService.GetCustomers(ctx, apiUrl, apiKey)
					if err == nil {
						for _, customer := range customers {
							email := strings.TrimSpace(customer.Email)
							if email != "" {
								emailSet[email] = struct{}{}
							}
						}
					}
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
