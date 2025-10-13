package helpers

import (
	"os"
	"strconv"

	billingDomain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/billing"
)

func GetInvoiceConfigFromEnv() *billingDomain.InvoiceConfig {
	documentIDStr := os.Getenv("INVOICE_DOCUMENT_ID")
	sellerIDStr := os.Getenv("INVOICE_SELLER_ID")
	paymentIDStr := os.Getenv("INVOICE_PAYMENT_ID")
	taxIDStr := os.Getenv("INVOICE_TAX_ID")

	documentID, _ := strconv.Atoi(documentIDStr)
	sellerID, _ := strconv.Atoi(sellerIDStr)
	paymentID, _ := strconv.Atoi(paymentIDStr)
	taxID, _ := strconv.Atoi(taxIDStr)

	return &billingDomain.InvoiceConfig{
		DocumentID: documentID,
		SellerID:   sellerID,
		PaymentID:  paymentID,
		TaxID:      taxID,
	}
}
