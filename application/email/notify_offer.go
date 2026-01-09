package services

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	services "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/ecommerce"
	blackListService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/email_black_list"
	application "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/file_storage"
	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/repository"
	"github.com/golang-jwt/jwt"
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

	blackListEmails, err := uc.emailBlackListService.GetBlackListEmails()
	if err != nil {
		log.Printf("error al obtener emails desde dynamo: %v", err)
	}

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
				if _, exists := blackListEmails[email]; !exists {
					emailSet[email] = struct{}{}
				}
			}
		}
	} else {
		credentials, err := uc.ecommerceCredentialsSvc.GetCredentials(ctx, posID)
		if err == nil {
			customers, err := uc.ecommerceService.GetCustomers(credentials.Context, credentials.ApiURL, credentials.ApiKey)
			if err == nil {
				for _, customer := range customers {
					email := strings.TrimSpace(customer.Email)
					if email != "" {
						if _, exists := blackListEmails[email]; !exists {
							emailSet[email] = struct{}{}
						}
					}
				}
			}
		}
	}

	u, err := url.Parse(auctionURL)
	if err != nil {
		log.Fatal("URL inválida:", err)
	}
	query := u.Query()
	tokenString := query.Get("token")

	if tokenString == "" {
		fmt.Printf("Token is missing")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", token.Header["alg"])
		}
		return []byte("JWT_SECRET"), nil
	})

	if err != nil {
		fmt.Printf("Invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		fmt.Printf("Invalid token")
	}

	expFloat, ok := claims["exp"].(float64)
	if !ok {
		fmt.Printf("exp no encontrado")
	}

	expiration := time.Unix(int64(expFloat), 0)
	location, _ := time.LoadLocation("America/Bogota")
	expiration = expiration.In(location)

	monthNames := []string{
		"enero", "febrero", "marzo", "abril", "mayo", "junio",
		"julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre",
	}
	expirationDate := fmt.Sprintf("%02d de %s de %d, %02d:%02d",
		expiration.Day(),
		strings.ToLower(monthNames[int(expiration.Month())-1]),
		expiration.Year(),
		expiration.Hour(),
		expiration.Minute(),
	)

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
