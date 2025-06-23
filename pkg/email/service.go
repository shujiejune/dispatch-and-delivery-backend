package email

import "context"

type ServiceInterface interface {
	SendEmail(ctx context.Context, to []string, subject, htmlBody, textBody string) error
}
