package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	blackListService "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/email_black_list"
	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/email_black_list"
)

type SNSNotificationService interface {
	HandleNotification(ctx context.Context, typer, message, subscriptionUrl string) (string, error)
	AddEmailToBlackList(ctx context.Context, email string ) (*domain.EmailBlackList, error)
}

type snsNotificationService struct {
	blackListService blackListService.EmailBlackListService
}

func NewSNSNotificationService(
	blackListService blackListService.EmailBlackListService,
) SNSNotificationService {
	return &snsNotificationService{
		blackListService: blackListService,
	}
}

type SESBounceNotification struct {
	EventType string `json:"eventType"`
	Bounce           struct {
		BounceType        string `json:"bounceType"`
		BouncedRecipients []struct {
			EmailAddress   string `json:"emailAddress"`
			Status         string `json:"status"`
			DiagnosticCode string `json:"diagnosticCode"`
		} `json:"bouncedRecipients"`
	} `json:"bounce"`
}

func (s snsNotificationService) HandleNotification(ctx context.Context, typer, message, subscriptionUrl string) (string, error){
	switch typer {
	case "SubscriptionConfirmation":
		fmt.Println("Confirmando suscripción a SNS:", subscriptionUrl)

		resp, err := http.Get(subscriptionUrl)
		if err != nil {
			return "", fmt.Errorf("failed to confirm subscription: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("failed to confirm subscription, status code: %d", resp.StatusCode)
		}
		return "Subscription confirmed", nil

	case "Notification":
		var bounce SESBounceNotification
		if err := json.Unmarshal([]byte(message), &bounce); err != nil {
			return "", fmt.Errorf("not SES Bounce, ignoring")
		}

		if bounce.EventType == "Bounce" {
			var processed []string

			for _, recipient := range bounce.Bounce.BouncedRecipients {
				_, err := s.blackListService.CreateBlackListItem(ctx, recipient.EmailAddress)
				if err != nil {
					return "", fmt.Errorf("failed to add %s to blackList: %w", recipient.EmailAddress, err)
				}
				processed = append(processed, recipient.EmailAddress)
			}

			if len(processed) > 0 {
				return fmt.Sprintf("Emails added successfully to blacklist: %v", processed), nil
			}

			return "Notification received but not a bounce", nil
		}
	}

	return "Unhandled SNS message type", nil
}


func (s snsNotificationService) AddEmailToBlackList(ctx context.Context, email string ) (*domain.EmailBlackList, error) {
	emails, err := s.blackListService.CreateBlackListItem(ctx, email)
	if err != nil {
		return &domain.EmailBlackList{}, err
	}
	return emails, nil
}