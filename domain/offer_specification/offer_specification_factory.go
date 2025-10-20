package domain

import (
	"fmt"
	"time"
)

type OfferSpecificationFactory interface {
	CreateOfferSpecification(externalID, offerID string) (*OfferSpecification, error)
}

type DefaultOfferSpecificationFactory struct{}

// NewOfferSpecificationFactory creates a new instance of the default offer specification factory
func NewOfferSpecificationFactory() OfferSpecificationFactory {
	return &DefaultOfferSpecificationFactory{}
}

// CreateOfferSpecification creates a new offer specification instance with the provided details, validating required fields
func (f *DefaultOfferSpecificationFactory) CreateOfferSpecification(externalID, offerID string) (*OfferSpecification, error) {
	if externalID == "" {
		return nil, fmt.Errorf("ExternalID cannot be empty")
	}
	if offerID == "" {
		return nil, fmt.Errorf("OfferID cannot be empty")
	}
	return &OfferSpecification{
		ExternalID: externalID,
		CreatedAt:  time.Now(),
		OfferID:    offerID,
	}, nil
}
