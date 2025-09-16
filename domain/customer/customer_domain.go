package domain

import "time"

type Customer struct {
	ID        int       `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Phone     string    `json:"phone"`
	Address   string    `json:"address"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type CustomerRepository interface {
	GetCustomers() ([]Customer, error)
	GetCustomerByID(id string) (*Customer, error)
}
