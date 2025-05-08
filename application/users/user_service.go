package services

import (
	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/user"
	infrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/user"
)

type UserService interface {
	GetAllUsers() ([]domain.User, error)
	AuthenticateUser(email, password string) (*infrastructure.AuthResponse, error)
	SignOut(token string) error
	ResetPassword(email string) error
	SetNewPassword(token, password string) error
	GetSessionByRefreshToken(refreshToken string) (*infrastructure.AuthResponse, error)
	RefreshSession(refreshToken string) (*infrastructure.AuthResponse, error)
}

type userService struct {
	repo infrastructure.UserRepository
}

func NewUserService(repo infrastructure.UserRepository) UserService {
	return &userService{repo: repo}
}

func (s *userService) GetAllUsers() ([]domain.User, error) {
	users, err := s.repo.GetAllUsers()
	if err != nil {
		return nil, err
	}

	return users, nil
}

func (s *userService) AuthenticateUser(email, password string) (*infrastructure.AuthResponse, error) {
	return s.repo.AuthenticateUser(email, password)
}

func (s *userService) SignOut(token string) error {
	return s.repo.SignOut(token)
}

func (s *userService) ResetPassword(email string) error {
	return s.repo.ResetPassword(email)
}

func (s *userService) SetNewPassword(token, password string) error {
	return s.repo.SetNewPassword(token, password)
}

func (s *userService) GetSessionByRefreshToken(refreshToken string) (*infrastructure.AuthResponse, error) {
	return s.repo.GetSessionByRefreshToken(refreshToken)
}

func (s *userService) RefreshSession(refreshToken string) (*infrastructure.AuthResponse, error) {
	return s.repo.RefreshSession(refreshToken)
}
