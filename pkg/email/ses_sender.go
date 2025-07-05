package email

import (
	"context"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
)

// SESV2Sender implements the EmailSender interface using AWS SES v2.
type SESV2Sender struct {
	client    *sesv2.Client
	fromEmail string
}

type ServiceInterface interface {
	SendEmail(ctx context.Context, to, subject, plainTextContent, htmlContent string) error
}

// NewSESV2Sender creates a new sender for Amazon SES.
// It automatically loads credentials from the environment
func NewSESV2Sender(ctx context.Context, region, fromEmail string) (*SESV2Sender, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, err
	}

	return &SESV2Sender{
		client:    sesv2.NewFromConfig(cfg),
		fromEmail: fromEmail,
	}, nil
}

// Send sends an email using the AWS SES v2 API.
func (s *SESV2Sender) SendEmail(ctx context.Context, to, subject, plainTextContent, htmlContent string) error {
	input := &sesv2.SendEmailInput{
		FromEmailAddress: &s.fromEmail,
		Destination: &types.Destination{
			ToAddresses: []string{to},
		},
		Content: &types.EmailContent{
			Simple: &types.Message{
				Subject: &types.Content{
					Data:    &subject,
					Charset: aws.String("UTF-8"),
				},
				Body: &types.Body{
					Text: &types.Content{
						Data:    &plainTextContent,
						Charset: aws.String("UTF-8"),
					},
					Html: &types.Content{
						Data:    &htmlContent,
						Charset: aws.String("UTF-8"),
					},
				},
			},
		},
	}

	_, err := s.client.SendEmail(ctx, input)
	if err != nil {
		log.Printf("Failed to send email via SES: %v", err)
		return err
	}

	log.Printf("Successfully sent email to %s", to)
	return nil
}
