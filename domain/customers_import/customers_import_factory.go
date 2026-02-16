package domain

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

type CustomersImportFactory interface {
	GenerateCustomersImport(name, posId, typer, url string) (*CustomersImport, error)
}

type DefaultCustomersImportFactory struct{}

func NewCustomersImportFactory() CustomersImportFactory {
	return &DefaultCustomersImportFactory{}
}

func (f *DefaultCustomersImportFactory) GenerateCustomersImport(name, posId, typer, url string) (*CustomersImport, error) {
	if name == "" {
		return nil, fmt.Errorf("name no puede estar vacío")
	}
	if posId == "" {
		return nil, fmt.Errorf("posId no puede estar vacío")
	}
	if typer == "" {
		return nil, fmt.Errorf("type no puede estar vacío")
	}
	if url == "" {
		return nil, fmt.Errorf("url no puede estar vacío")
	}

	return &CustomersImport{
		Id:       generateUUID(),
		Name:     name,
		PosId:    posId,
		Type:     typer,
		Url:      url,
		LastSync: time.Now(),
	}, nil
}

func generateUUID() string {
	return uuid.New().String()
}
