package email

import (
	"context"
	"fmt"
	"net/smtp"
	// "jingdezhen-ceramics-backend/internal/config" // If SMTP settings are in config
)

type SMTPService struct {
	auth      smtp.Auth
	smtpHost  string
	smtpPort  string
	fromEmail string
}

// NewSMTPService creates a basic SMTP email sender
// In a real app, smtpHost, port, user, pass, fromEmail come from config
func NewSMTPService(host, port, user, password, from string) ServiceInterface {
	auth := smtp.PlainAuth("", user, password, host)
	return &SMTPService{
		auth:      auth,
		smtpHost:  host,
		smtpPort:  port,
		fromEmail: from,
	}
}

func (s *SMTPService) SendEmail(ctx context.Context, to []string, subject, htmlBody, textBody string) error {
	// For HTML emails, you need to set MIME headers
	// This is a simplified text-only example
	msg := []byte("To: " + to[0] + "\r\n" + // Simplified for one recipient
		"From: " + s.fromEmail + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"\r\n" +
		textBody + "\r\n")

	addr := fmt.Sprintf("%s:%s", s.smtpHost, s.smtpPort)
	err := smtp.SendMail(addr, s.auth, s.fromEmail, to, msg)
	if err != nil {
		return fmt.Errorf("smtp.SendMail failed: %w", err)
	}
	return nil
}
