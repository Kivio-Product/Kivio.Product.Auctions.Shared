package services

import (
	"fmt"

	ruleDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/rule"
	sheetsDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/sheets"
	integrationInfrastructure "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/persistence/dynamodb/integration"
)

type SheetService interface {
	FetchSheetData(pointOfSaleId string) (sheetsDomain.SheetData, error)
	InferFields(sheetData sheetsDomain.SheetData) []sheetsDomain.RuleField
}

type sheetService struct {
	repo                  integrationInfrastructure.GoogleSheetsRepository
	integrationRepository integrationInfrastructure.IntegrationRepository
}

func NewSheetService(repo integrationInfrastructure.GoogleSheetsRepository, integrationRepository integrationInfrastructure.IntegrationRepository) SheetService {
	return &sheetService{repo: repo, integrationRepository: integrationRepository}
}

func (s *sheetService) FetchSheetData(pointOfSaleId string) (sheetsDomain.SheetData, error) {
	integrations, err := s.integrationRepository.GetIntegrationsByPosID(pointOfSaleId)
	if err != nil {
		return sheetsDomain.SheetData{}, err
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
		return sheetsDomain.SheetData{}, fmt.Errorf("missing Google Sheets configuration for pointOfSaleId %s", pointOfSaleId)
	}
	return s.repo.GetSheetData(spreadsheetId, readRange)
}

func (s *sheetService) InferFields(sheetData sheetsDomain.SheetData) []sheetsDomain.RuleField {
	headers := sheetData.Values[0]
	sampleData := sheetData.Values[1:]

	var fields []sheetsDomain.RuleField
	for colIndex, h := range headers {
		values := ruleDomain.ExtractColumnValues(sampleData, colIndex)
		typeDetected := ruleDomain.InferType(values)
		operators := sheetsDomain.TypeToOperators[typeDetected]
		fields = append(fields, sheetsDomain.RuleField{
			Field:         fmt.Sprintf("%v", h),
			ParameterType: typeDetected,
			Operators:     operators,
		})
	}
	return fields
}
