package domain

import "errors"

type RuleSpecification struct {
	RuleSpecificationId string
	RuleId              string
	OfferId             string
	Type                string
	Operator            string
	Parameter           string
	ItemName            string
	State               bool
}

func GenerateInactiveState(rule *RuleSpecification) *RuleSpecification {
	rule.State = false
	return rule
}

func (o *RuleSpecification) Update(typer, operator, parameter string) error {
	if typer == "" {
		return errors.New("El type no puede estar vacío")
	}
	if operator == "" {
		return errors.New("La operacion no puede estar vacía")
	}
	if parameter == "" {
		return errors.New("el parametro no puede estar vacía")
	}
	o.Type = typer
	o.Operator = operator
	o.Parameter = parameter
	return nil
}
