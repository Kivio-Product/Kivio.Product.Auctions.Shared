package infrastructure

import (
	"fmt"
	"os"
	"strconv"

	domainRepo "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/repository"
	"gopkg.in/gomail.v2"
)

type SMTPNotifier struct {
	dialer *gomail.Dialer
	sender string
}

func NewSMTPNotifier() (domainRepo.Notifier, error) {
	host := os.Getenv("SMTP_HOST")
	if host == "" {
		host = "smtpout.secureserver.net"
	}

	portStr := os.Getenv("SMTP_PORT")
	if portStr == "" {
		portStr = "587"
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("SMTP_PORT debe ser un número válido: %w", err)
	}

	username := os.Getenv("SMTP_USERNAME")
	if username == "" {
		return nil, fmt.Errorf("SMTP_USERNAME environment variable is required")
	}

	password := os.Getenv("SMTP_PASSWORD")
	if password == "" {
		return nil, fmt.Errorf("SMTP_PASSWORD environment variable is required")
	}

	sender := os.Getenv("SMTP_SENDER_EMAIL")
	if sender == "" {
		sender = username
	}

	dialer := gomail.NewDialer(host, port, username, password)

	return &SMTPNotifier{
		dialer: dialer,
		sender: sender,
	}, nil
}

func (n *SMTPNotifier) SendEmail(email, subject, body string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", n.sender)
	m.SetHeader("To", email)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	if err := n.dialer.DialAndSend(m); err != nil {
		return fmt.Errorf("error sending email via SMTP: %w", err)
	}

	return nil
}

func (n *SMTPNotifier) SendTemplatedEmail(email, templateName string, templateData map[string]string) error {
	subject := getSubjectFromTemplate(templateName)
	body := generateEmailBody(templateName, templateData)

	return n.SendEmail(email, subject, body)
}

func getSubjectFromTemplate(templateName string) string {
	switch templateName {
	case "OfertaGeneral":
		return "Nueva Oferta Disponible"
	case "SubastaAprobada":
		return "Subasta Aprobada"
	case "SubastaRechazada":
		return "Subasta Rechazada"
	case "CompraRapida":
		return "Compra Rápida Confirmada"
	default:
		return "Notificación del Sistema"
	}
}

func generateEmailBody(templateName string, templateData map[string]string) string {
	body := "<html><body style='font-family: Arial, sans-serif;'>"

	switch templateName {
	case "OfertaGeneral":
		body += "<h2>Nueva Oferta Disponible</h2>"
		body += "<p>Se ha creado una nueva oferta: <strong>" + templateData["OFFER_DESCRIPTION"] + "</strong></p>"
		body += "<p>Puedes acceder a la subasta aquí: <a href='" + templateData["AUCTION_URL"] + "'>Ver Subasta</a></p>"
		body += "<p>Esta oferta expira el: " + templateData["EXPIRATION_DATE"] + "</p>"

	case "SubastaAprobada":
		body += "<h2>Subasta Aprobada</h2>"
		body += "<p>Tu subasta ha sido aprobada exitosamente.</p>"
		body += "<p>Producto: <strong>" + templateData["ITEM_NAME"] + "</strong></p>"
		body += "<p>Monto: $" + templateData["AMOUNT"] + "</p>"
		if templateData["ITEM_DESCRIPTION"] != "" {
			body += "<p>Descripción: " + templateData["ITEM_DESCRIPTION"] + "</p>"
		}

	case "SubastaRechazada":
		body += "<h2>Subasta Rechazada</h2>"
		body += "<p>Tu subasta ha sido rechazada.</p>"
		body += "<p>Producto: <strong>" + templateData["ITEM_NAME"] + "</strong></p>"
		body += "<p>Monto: $" + templateData["AMOUNT"] + "</p>"
		if templateData["ITEM_DESCRIPTION"] != "" {
			body += "<p>Descripción: " + templateData["ITEM_DESCRIPTION"] + "</p>"
		}

	case "CompraRapida":
		body += "<h2>Compra Rápida Confirmada</h2>"
		body += "<p>Tu compra rápida ha sido procesada exitosamente.</p>"
		body += "<p>Producto: <strong>" + templateData["ITEM_NAME"] + "</strong></p>"
		body += "<p>Monto: $" + templateData["AMOUNT"] + "</p>"
		if templateData["ITEM_DESCRIPTION"] != "" {
			body += "<p>Descripción: " + templateData["ITEM_DESCRIPTION"] + "</p>"
		}

	default:
		body += "<h2>Notificación del Sistema</h2>"
		body += "<p>Has recibido una notificación del sistema.</p>"
	}

	body += "<br><p>Saludos,<br>Equipo de Kivio</p>"
	body += "</body></html>"

	return body
}
