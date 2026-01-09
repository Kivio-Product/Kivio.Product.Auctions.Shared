package domain

// BillingByOrder represents the relationship between billing and orders
// 
// This struct establishes the many-to-many relationship between billing records
// and orders, allowing multiple orders to be associated with a single billing
// transaction. It's used for tracking which orders are included in each payment.
type BillingByOrder struct {
	BillingId  string `json:"billingId" dynamodbav:"billingId"`
	OrderId    string `json:"orderId" dynamodbav:"orderId"`
	Id         string `json:"id" dynamodbav:"id"`
	CustomerId string `json:"customerId" dynamodbav:"customerId"`
	State      string `json:"state" dynamodbav:"state"`
}
