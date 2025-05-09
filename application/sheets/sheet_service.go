package services

import (
	"fmt"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Domain.Shared/sheets"
	sharedinfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Infrastructure.Shared"
	internalDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Rules/internal/domain"
)

type SheetService interface {
	FetchSheetData(pointOfSaleId string) (domain.SheetData, error)
	InferFields(sheetData domain.SheetData) []domain.RuleField
}

type sheetService struct {
	repo                  sharedinfrastructure.GoogleSheetsRepository
	integrationRepository sharedinfrastructure.IntegrationRepository
}

func NewSheetService(repo sharedinfrastructure.GoogleSheetsRepository, integrationRepository sharedinfrastructure.IntegrationRepository) SheetService {
	return &sheetService{repo: repo, integrationRepository: integrationRepository}
}

func (s *sheetService) FetchSheetData(pointOfSaleId string) (domain.SheetData, error) {
	integrations, err := s.integrationRepository.GetIntegrationsByPosID(pointOfSaleId)
	if err != nil {
		return domain.SheetData{}, err
	}

	var spreadsheetId, readRange string

	for _, integration := range integrations {
		for _, config := range integration.Configs {
			if config.Key == "spreadsheetId" {
				spreadsheetId = config.Value
			} else if config.Key == "readRange" {
				readRange = config.Value
			}
		}
	}

	if spreadsheetId == "" || readRange == "" {
		return domain.SheetData{}, fmt.Errorf("missing Google Sheets configuration for pointOfSaleId %s", pointOfSaleId)
	}
	return s.repo.GetSheetData(spreadsheetId, readRange)
}

func (s *sheetService) InferFields(sheetData domain.SheetData) []domain.RuleField {
	headers := sheetData.Values[0]
	sampleData := sheetData.Values[1:]

	var fields []domain.RuleField
	for colIndex, h := range headers {
		values := internalDomain.ExtractColumnValues(sampleData, colIndex)
		typeDetected := internalDomain.InferType(values)
		operators := domain.TypeToOperators[typeDetected]
		fields = append(fields, domain.RuleField{
			Field:         fmt.Sprintf("%v", h),
			ParameterType: typeDetected,
			Operators:     operators,
		})
	}
	return fields
}
