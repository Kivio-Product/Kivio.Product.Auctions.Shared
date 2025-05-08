package domain

import "fmt"

type Item struct {
	ItemId        string
	Name          string
	Description   string
	ExternalId    string
	PointOfSaleId string
	Url           string
	Source        string
}

func (o *Item) Update(name, description, externalId, pointOfSaleId, url string) error {

	if name == "" {
		return fmt.Errorf("Name cannot be empty")
	}
	if description == "" {
		return fmt.Errorf("Description cannot be empty")
	}
	if pointOfSaleId == "" {
		return fmt.Errorf("PointOfSaleId cannot be empty")
	}

	o.Name = name
	o.Description = description
	o.ExternalId = externalId
	o.PointOfSaleId = pointOfSaleId
	o.Url = url

	return nil
}
