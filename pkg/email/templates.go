package email

import (
	"bytes"
	"html/template"
	"log"
)

// TemplateManager holds the parsed email templates.
type TemplateManager struct {
	ActivationTmpl *template.Template
	ResetPassTmpl  *template.Template
}

// NewTemplateManager parses all email templates at startup.
func NewTemplateManager() (*TemplateManager, error) {
	activationTmpl, err := template.New("activation").Parse(accountActivTemplate)
	if err != nil {
		return nil, err
	}

	resetPassTmpl, err := template.New("resetPassword").Parse(passwordResetTemplate)
	if err != nil {
		return nil, err
	}

	log.Println("Email templates parsed successfully.")
	return &TemplateManager{
		ActivationTmpl: activationTmpl,
		ResetPassTmpl:  resetPassTmpl,
	}, nil
}

// TemplateData holds the dynamic data for an email template.
type TemplateData struct {
	Name string
	Link string
}

// GenerateActivationEmailHTML executes the activation template with the provided data.
func (tm *TemplateManager) GenerateActivateAccountEmailHTML(data TemplateData) (string, error) {
	var body bytes.Buffer
	if err := tm.ActivationTmpl.Execute(&body, data); err != nil {
		return "", err
	}
	return body.String(), nil
}

// GenerateResetPasswordEmailHTML executes the password reset template.
func (tm *TemplateManager) GenerateResetPasswordEmailHTML(data TemplateData) (string, error) {
	var body bytes.Buffer
	if err := tm.ResetPassTmpl.Execute(&body, data); err != nil {
		return "", err
	}
	return body.String(), nil
}

// --- HTML Template Definitions ---

const accountActivTemplate = `
<!DOCTYPE html>
<html>
<head>
	<title>Activate Your Account</title>
</head>
<body style="font-family: Arial, sans-serif;">
	<h2>Welcome to Our Service, {{.Name}}!</h2>
	<p>Thank you for signing up. Please click the link below to activate your account:</p>
	<p><a href="{{.Link}}">Activate Account</a></p>
	<p>This link will expire in 30 minutes.</p>
	<p>If you did not sign up for this account, please ignore this email.</p>
</body>
</html>
`

const passwordResetTemplate = `
<!DOCTYPE html>
<html>
<head>
	<title>Reset Your Password</title>
</head>
<body style="font-family: Arial, sans-serif;">
	<h2>Password Reset Request</h2>
	<p>Hello {{.Name}},</p>
	<p>We received a request to reset your password. Please click the link below to set a new password:</p>
	<p><a href="{{.Link}}">Reset Password</a></p>
	<p>This link will expire in 15 minutes.</p>
	<p>If you did not request a password reset, please ignore this email.</p>
</body>
</html>
`
