package services

import (
	"context"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/email_black_list"
	infrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/email_black_list"
)

type EmailBlackListService interface {
	CreateBlackListItem(ctx context.Context, email string) (*domain.EmailBlackList, error)
	GetBlackListEmails() (map[string]struct{}, error)
}

type emailBlackListService struct {
	repo                  infrastructure.EmailBlackListRepository
	emailBlackListFactory domain.EmailBlackListFactory
}

func NewEmailBlackListService(
	repo infrastructure.EmailBlackListRepository,
	emailBlackListFactory domain.EmailBlackListFactory,

) EmailBlackListService {
	return &emailBlackListService{
		repo:                  repo,
		emailBlackListFactory: emailBlackListFactory,
	}
}

func (s *emailBlackListService) CreateBlackListItem(ctx context.Context, email string) (*domain.EmailBlackList, error) {
	emailBlackList, err := s.emailBlackListFactory.Create(email)
	if err != nil {
		return &domain.EmailBlackList{}, err
	}
	if err := s.repo.Save(ctx, emailBlackList); err != nil {
		return &domain.EmailBlackList{}, err
	}
	return emailBlackList, nil
}

func (s *emailBlackListService) GetBlackListEmails() (map[string]struct{}, error) {
	emails, err := s.repo.GetBlackListEmails()
	if err != nil {
		return nil, err
	}
	return emails, nil
}
