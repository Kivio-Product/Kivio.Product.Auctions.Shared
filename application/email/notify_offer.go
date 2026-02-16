package services

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	services "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/ecommerce"
	blackListService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/email_black_list"
	application "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/file_storage"
	integrationsService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/integration"
	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/repository"
	"github.com/golang-jwt/jwt/v5"
)

type NotifyOfferUseCase struct {
	notifier                domain.Notifier
	fileStorageService      application.IFileStorageService
	ecommerceService        services.EcommerceService
	ecommerceCredentialsSvc services.EcommerceCredentialsService
	emailBlackListService   blackListService.EmailBlackListService
	integrationsService     integrationsService.IntegrationService
}

func NewNotifyOfferUseCase(
	notifier domain.Notifier,
	fileStorageService application.IFileStorageService,
	ecommerceService services.EcommerceService,
	ecommerceCredentialsSvc services.EcommerceCredentialsService,
	emailBlackListService blackListService.EmailBlackListService,
	integrationsService integrationsService.IntegrationService,
) *NotifyOfferUseCase {
	return &NotifyOfferUseCase{
		notifier:                notifier,
		fileStorageService:      fileStorageService,
		ecommerceService:        ecommerceService,
		ecommerceCredentialsSvc: ecommerceCredentialsSvc,
		emailBlackListService:   emailBlackListService,
		integrationsService:     integrationsService,
	}
}

func (uc *NotifyOfferUseCase) Execute(ctx context.Context, auctionURL, unsubscribeUrl, offerName, posID, posName string) error {
	emailSet := make(map[string]struct{})
	integrations, err := uc.integrationsService.GetIntegrationsByPosID(ctx, posID)
	if err != nil {
		log.Printf("error al obtener integraciones: %v", err)
	}
	hasEcommerce := false

	for _, integration := range integrations {
		if integration.Name == "Kivio Ecommerce" {
			hasEcommerce = true
			break
		}
	}

	blackListEmails, err := uc.emailBlackListService.GetBlackListEmails()
	if err != nil {
		log.Printf("error al obtener emails desde dynamo: %v", err)
	}

	if hasEcommerce == true {
		log.Printf("[DEBUG] SHOULD_RETRIEVE_S3_EMAILS es false, obteniendo emails desde ecommerce para posID: %s", posID)
		credentials, err := uc.ecommerceCredentialsSvc.GetCredentials(ctx, posID)
		if err == nil {
			log.Printf("[DEBUG] Credenciales obtenidas exitosamente para posID: %s", posID)
			emails, err := uc.ecommerceService.GetCustomerEmails(credentials.Context, credentials.ApiURL, credentials.ApiKey)
			if err == nil {
				log.Printf("[DEBUG] Se obtuvieron %d emails desde ecommerce", len(emails))
				emailsBeforeFilter := len(emails)
				emailsFiltered := 0
				for _, email := range emails {
					email = strings.TrimSpace(email)
					if email != "" {
						if _, exists := blackListEmails[email]; !exists {
							emailSet[email] = struct{}{}
						} else {
							emailsFiltered++
							log.Printf("[DEBUG] Email filtrado por blacklist: %s", email)
						}
					}
				}
				log.Printf("[DEBUG] Emails procesados: %d total, %d filtrados por blacklist, %d agregados a emailSet", emailsBeforeFilter, emailsFiltered, len(emailSet))
			} else {
				log.Printf("[ERROR] Error al obtener emails desde ecommerce: %v", err)
			}
		} else {
			log.Printf("[ERROR] Error al obtener credenciales para posID %s: %v", posID, err)
		}

	} else {
		cleanName := strings.ReplaceAll(posName, " ", "-")
		s3Key := fmt.Sprintf("files/customers-%s.csv", cleanName)

		content, err := uc.fileStorageService.ReadFile(ctx, s3Key)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			if i == 0 {
				continue
			}

			var columns []string
			if strings.Contains(line, ";") {
				columns = strings.Split(line, ";")
			} else {
				columns = strings.Split(line, ",")
			}
			if len(columns) == 0 {
				continue
			}

			email := strings.TrimSpace(columns[1])
			if email == "" {
				continue
			}

			if _, blacklisted := blackListEmails[email]; blacklisted {
				continue
			}

			emailSet[email] = struct{}{}
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

	log.Printf("[DEBUG] Iniciando envío de emails. Total de destinatarios en emailSet: %d", len(emailSet))
	emailsSent := 0
	emailsWithError := 0

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
			emailsWithError++
			fmt.Printf("Error enviando a %s: %v\n", email, err)
			log.Printf("[ERROR] Error enviando email a %s: %v", email, err)
		} else {
			emailsSent++
			log.Printf("[DEBUG] Email enviado exitosamente a: %s", email)
		}
	}

	log.Printf("[DEBUG] Resumen de envío: %d emails enviados exitosamente, %d emails con error, de un total de %d destinatarios", emailsSent, emailsWithError, len(emailSet))
	return nil
}

func addCustomerIdParam(url, email string) string {
	sep := "?"
	if strings.Contains(url, "?") {
		sep = "&"
	}
	return url + sep + "customerId=" + email
}
