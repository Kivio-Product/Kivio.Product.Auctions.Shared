package services

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	applicationLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/logging"
	"github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/logging"
	ruleSpecDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/rule_specification"
	infrastructureLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/logging"
)

type RuleValidationService interface {
	ValidateRules(ctx context.Context, rules []ruleSpecDomain.RuleSpecification) bool
}

type ruleValidationService struct {
	serviceLogger *applicationLogging.ServiceLogger
	eventLogger   *logging.DomainEventLogger
}

func NewRuleValidationService() RuleValidationService {
	loggerRepo := infrastructureLogging.GetLoggerRepository()
	serviceLogger := applicationLogging.NewServiceLogger(loggerRepo, "RuleValidationService")
	eventLogger := logging.NewDomainEventLogger(loggerRepo.GetLogger())

	return &ruleValidationService{
		serviceLogger: serviceLogger,
		eventLogger:   eventLogger,
	}
}

func (s *ruleValidationService) ValidateRules(ctx context.Context, rules []ruleSpecDomain.RuleSpecification) bool {
	valid := s.validateRuleSpecifications(ctx, rules)
	return valid
}

func (s *ruleValidationService) validateRuleSpecifications(
	ctx context.Context,
	specifications []ruleSpecDomain.RuleSpecification,
) bool {
	groupedRules := groupRuleSpecsByParameter(specifications)

	for parameter, spec := range groupedRules {
		if !s.validateSpecification(ctx, parameter, spec) {
			return false
		}
	}
	return true
}

func (s *ruleValidationService) validateSpecification(
	ctx context.Context,
	parameter string,
	rules []ruleSpecDomain.RuleSpecification,
) bool {

	switch parameter {

	case "current date", "AvailableStartDate", "AvailableEndDate":
		return validateDateSpecification(rules)

	case "availability", "StockQuantity":
		return validateNumericSpecification(rules)

	case "Price", "OldPrice", "Weight":
		return validateNumericValue(rules)

	case "Published", "VisibleIndividually", "IsFreeShipping":
		return validateBooleanValue(rules)

	case "Tags":
		return validateCategoryValue(rules)

	default:
		fmt.Printf("Parámetro desconocido o no manejado %s.\n", parameter)
	}

	return false
}

func validateNumericSpecification(rules []ruleSpecDomain.RuleSpecification) bool {

	var lowerBound *int64
	var upperBound *int64

	mustContain := map[int64]bool{}
	cannotContain := map[int64]bool{}

	for _, rule := range rules {

		expected, err := strconv.ParseInt(rule.Type, 10, 64)
		if err != nil {
			fmt.Printf("Error al parsear spec.Type '%s' como int64: %v\n", rule.Type, err)
			return false
		}

		switch rule.Operator {

		case ">":
			strictValue := expected + 1
			if lowerBound == nil || strictValue > *lowerBound {
				lowerBound = &strictValue
			}

		case ">=":
			if lowerBound == nil || expected > *lowerBound {
				lowerBound = &expected
			}

		case "<=":
			if upperBound == nil || expected < *upperBound {
				upperBound = &expected
			}

		case "<":
			strictValue := expected - 1
			if upperBound == nil || strictValue < *upperBound {
				upperBound = &strictValue
			}

		case "=":
			if cannotContain[expected] {
				return false
			}

			if len(mustContain) > 0 {
				for v := range mustContain {
					if v != expected {
						return false
					}
				}
			}

			mustContain[expected] = true

		case "!=":
			if mustContain[expected] {
				return false
			}

			cannotContain[expected] = true

		default:
			fmt.Printf("Operador desconocido '%s'.\n", rule.Operator)
			return false
		}
	}

	if lowerBound != nil && upperBound != nil && *lowerBound > *upperBound {
		return false
	}

	for v := range mustContain {
		if lowerBound != nil && v < *lowerBound {
			return false
		}
		if upperBound != nil && v > *upperBound {
			return false
		}
		if cannotContain[v] {
			return false
		}
	}

	if lowerBound != nil && upperBound != nil && *lowerBound == *upperBound {
		single := *lowerBound
		if cannotContain[single] {
			return false
		}
	}

	return true
}

func validateNumericValue(rules []ruleSpecDomain.RuleSpecification) bool {

	var lowerBound *float64
	var upperBound *float64

	mustContain := map[float64]bool{}
	cannotContain := map[float64]bool{}

	for _, rule := range rules {

		cleanStr := strings.ReplaceAll(rule.Type, ".", "")
		parameterValue, err := strconv.ParseFloat(cleanStr, 64)
		if err != nil {
			fmt.Printf("Error al parsear spec.Type '%s' como float64 en validateNumericValue: %v\n", rule.Type, err)
			return false
		}

		switch rule.Operator {
		case ">":
			strictValue := parameterValue + 0.0001
			if lowerBound == nil || strictValue > *lowerBound {
				lowerBound = &strictValue
			}

		case ">=":
			if lowerBound == nil || parameterValue > *lowerBound {
				lowerBound = &parameterValue
			}

		case "<=":
			if upperBound == nil || parameterValue < *upperBound {
				upperBound = &parameterValue
			}

		case "<":
			strictValue := parameterValue - 0.0001
			if upperBound == nil || strictValue < *upperBound {
				upperBound = &strictValue
			}
		case "=":
			if cannotContain[parameterValue] {
				return false
			}

			if len(mustContain) > 0 {
				for v := range mustContain {
					if v != parameterValue {
						return false
					}
				}
			}

			mustContain[parameterValue] = true

		case "!=":
			if mustContain[parameterValue] {
				return false
			}

			cannotContain[parameterValue] = true

		default:
			fmt.Printf("Operador desconocido '%s'.\n", rule.Operator)
			return false
		}
	}

	if lowerBound != nil && upperBound != nil && *lowerBound > *upperBound {
		return false
	}

	for v := range mustContain {
		if lowerBound != nil && v < *lowerBound {
			return false
		}
		if upperBound != nil && v > *upperBound {
			return false
		}
		if cannotContain[v] {
			return false
		}
	}

	if lowerBound != nil && upperBound != nil && *lowerBound == *upperBound {
		single := *lowerBound
		if cannotContain[single] {
			return false
		}
	}

	return true
}

func validateDateSpecification(rules []ruleSpecDomain.RuleSpecification) bool {

	var lowerBound *time.Time
	var upperBound *time.Time

	mustContain := map[time.Time]bool{}
	cannotContain := map[time.Time]bool{}

	for _, rule := range rules {

		dateStr := rule.Type
		if idx := strings.Index(dateStr, "("); idx != -1 {
			dateStr = strings.TrimSpace(dateStr[:idx])
		}

		formats := []string{
			time.RFC3339,
			"Mon Jan 02 2006 15:04:05 GMT-0700",
			"Mon Jan 02 15:04:05 MST 2006",
			"2006-01-02",
		}

		var parameterDate time.Time
		var err error

		for _, format := range formats {
			parameterDate, err = time.Parse(format, dateStr)
			if err == nil {
				break
			}
		}
		if err != nil {
			fmt.Printf("Error al parsear fecha '%s': %v\n", dateStr, err)
			return false
		}

		switch rule.Operator {

		case ">":
			strictDate := parameterDate.AddDate(0, 0, 1)
			if lowerBound == nil || strictDate.After(*lowerBound) {
				lowerBound = &strictDate
			}

		case ">=":
			if lowerBound == nil || parameterDate.After(*lowerBound) {
				lowerBound = &parameterDate
			}

		case "<":
			strictDate := parameterDate.AddDate(0, 0, -1)
			if upperBound == nil || strictDate.Before(*upperBound) {
				upperBound = &strictDate
			}

		case "<=":
			if upperBound == nil || parameterDate.Before(*upperBound) {
				upperBound = &parameterDate
			}

		case "=":

			if cannotContain[parameterDate] {
				return false
			}
			mustContain[parameterDate] = true

			if lowerBound == nil || parameterDate.After(*lowerBound) {
				lowerBound = &parameterDate
			}
			if upperBound == nil || parameterDate.Before(*upperBound) {
				upperBound = &parameterDate
			}

		case "!=":

			if mustContain[parameterDate] {
				return false
			}
			cannotContain[parameterDate] = true

		default:
			fmt.Printf("Operador desconocido '%s' para comparación de fechas.\n", rule.Operator)
			return false
		}
	}

	if lowerBound != nil && upperBound != nil && lowerBound.After(*upperBound) {
		return false
	}

	if lowerBound != nil && upperBound != nil && lowerBound.Equal(*upperBound) {
		if cannotContain[*lowerBound] {
			return false
		}
	}

	return true
}

func validateBooleanValue(rules []ruleSpecDomain.RuleSpecification) bool {
	var mustBe *bool
	var cannotBe *bool

	for _, rule := range rules {
		parameterValue, err := strconv.ParseBool(rule.Type)
		if err != nil {
			fmt.Printf("Error al parsear '%s' como bool: %v\n", rule.Type, err)
			return false
		}

		switch rule.Operator {
		case "=":

			if mustBe != nil && *mustBe != parameterValue {
				return false
			}
			mustBe = &parameterValue

			if cannotBe != nil && *cannotBe == parameterValue {
				return false
			}

		case "!=":
			if cannotBe != nil && *cannotBe != parameterValue {
				return false
			}
			cannotBe = &parameterValue

			if mustBe != nil && *mustBe == parameterValue {
				return false
			}

		default:
			fmt.Printf("Operador desconocido '%s' para boolean.\n", rule.Operator)
			return false
		}
	}

	if cannotBe != nil && mustBe != nil && *cannotBe == *mustBe {
		return false
	}

	return true
}

func validateCategoryValue(rules []ruleSpecDomain.RuleSpecification) bool {

	mustContain := map[string]bool{}
	cannotContain := map[string]bool{}

	for _, rule := range rules {
		word := strings.ToLower(rule.Type)

		switch strings.ToLower(rule.Operator) {

		case "está en":
			if cannotContain[word] {
				return false
			}
			mustContain[word] = true

		case "no está en":
			if mustContain[word] {
				return false
			}
			cannotContain[word] = true

		default:
			fmt.Printf("Operador desconocido '%s' para comparación de categorías.\n", rule.Operator)
			return false
		}
	}

	return true
}

func groupRuleSpecsByParameter(rules []ruleSpecDomain.RuleSpecification) map[string][]ruleSpecDomain.RuleSpecification {
	grouped := make(map[string][]ruleSpecDomain.RuleSpecification)
	for _, rule := range rules {
		grouped[rule.Parameter] = append(grouped[rule.Parameter], rule)
	}
	return grouped
}
