package domain

import (
	"fmt"
)

type EmailBlackListFactory interface {
	Create(email string) (*EmailBlackList, error)
}

type DefaultEmailBlackListFactory struct{}

func NewEmailBlackListFactory() EmailBlackListFactory {
	return &DefaultEmailBlackListFactory{}
}

func (f *DefaultEmailBlackListFactory) Create(email string) (*EmailBlackList, error) {

	if email == "" {
		return nil, fmt.Errorf("Email cannot be empty")
	}

	return &EmailBlackList{
		Email: email,
	}, nil
}
