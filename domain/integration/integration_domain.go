package domain

import "time"

type IntegrationStatus string

const (
	Active    IntegrationStatus = "Active"
	Inactive  IntegrationStatus = "Inactive"
	Error     IntegrationStatus = "Error"
	Connected IntegrationStatus = "Connected"
)

type Integration struct {
	IntegrationID string              `json:"integrationId" dynamodbav:"integrationId"`
	Name          string              `json:"name" dynamodbav:"name"`
	PosID         string              `json:"posId" dynamodbav:"posId"`
	Type          string              `json:"type" dynamodbav:"type"`
	Status        IntegrationStatus   `json:"status" dynamodbav:"status"`
	LastSync      time.Time           `json:"lastSync" dynamodbav:"lastSync"`
	CreatedAt     time.Time           `json:"createdAt" dynamodbav:"createdAt"`
	Configs       []IntegrationConfig `json:"configs" dynamodbav:"-"`
}

type IntegrationConfig struct {
	IntegrationConfigID string `json:"integrationConfigId" dynamodbav:"integrationConfigId"`
	IntegrationID       string `json:"integrationId" dynamodbav:"integrationId"`
	Key                 string `json:"key" dynamodbav:"key"`
	Value               string `json:"value" dynamodbav:"value"`
}

type PointOfSale struct {
	ID          string    `json:"id" dynamodbav:"id"`
	Name        string    `json:"name" dynamodbav:"name"`
	Description string    `json:"description" dynamodbav:"description"`
	State       string    `json:"state" dynamodbav:"state"`
	CreatedAt   time.Time `json:"createdAt" dynamodbav:"createdAt"`
	UserID      string    `json:"userId" dynamodbav:"userId"`
}
