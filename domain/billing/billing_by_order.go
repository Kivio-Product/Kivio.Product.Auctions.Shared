package domain

type BillingByOrder struct {
	BillingId  string `json:"billingId" dynamodbav:"billingId"`
	OrderId    string `json:"orderId" dynamodbav:"orderId"`
	Id         string `json:"id" dynamodbav:"id"`
	CustomerId string `json:"customerId" dynamodbav:"customerId"`
	State      string `json:"state" dynamodbav:"state"`
}
