package domain

import (
	"time"
)

type CustomersImport struct {
	Id       string    `json:"id" dynamodbav:"id"`
	Name     string    `json:"name" dynamodbav:"name"`
	PosId    string    `json:"pos_id" dynamodbav:"posId"`
	Type     string    `json:"typer" dynamodbav:"type"`
	Url      string    `json:"url" dynamodbav:"url"`
	LastSync time.Time `json:"lastSync" dynamodbav:"lastSync"`
}
