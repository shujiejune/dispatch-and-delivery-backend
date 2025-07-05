package user

import (
	"context"
	"dispatch-and-delivery/internal/models"
	emailSvc "dispatch-and-delivery/pkg/email"
	"dispatch-and-delivery/pkg/utils"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

// ServiceInterface defines methods for user business logic.
type ServiceInterface interface {
	GetClientOrigin() string

	Signup(ctx context.Context, req models.SignupRequest) (*models.User, error)
	Login(ctx context.Context, req models.LoginRequest) (*models.AuthResponse, error)
	ActivateUserAndLogin(ctx context.Context, token string) (*models.AuthResponse, error)
	ResendActivationEmail(ctx context.Context, email string) error
	RequestPasswordReset(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, token string, newPassword string) (*models.AuthResponse, error)
	HandleGoogleLogin() (string, string, error)
	HandleGoogleCallback(ctx context.Context, code string) (*models.AuthResponse, error)

	GetUserProfile(ctx context.Context, userID string) (*models.User, error)
	UpdateUserProfile(ctx context.Context, userID string, data models.UserUpdateData) (*models.User, error)

	ListAddresses(ctx context.Context, userID string) ([]models.Address, error)
	AddAddress(ctx context.Context, userID, label, streetAddress string, isDefault bool) (*models.Address, error)
	UpdateAddress(ctx context.Context, userID, addressID string, req models.UpdateAddressRequest) (*models.Address, error)
	DeleteAddress(ctx context.Context, userID, addressID string) error
}

type Service struct {
	userRepo          RepositoryInterface
	emailer           emailSvc.ServiceInterface // For sending emails
	templateManager   *emailSvc.TemplateManager
	jwtSecret         string
	clientOrigin      string // For sending activation and password reset emails (domain name)
	googleOAuthConfig *oauth2.Config
}

func NewService(
	userRepo RepositoryInterface,
	emailer emailSvc.ServiceInterface,
	tm *emailSvc.TemplateManager,
	JWTSecretFromConfig string,
	clientOriginFromConfig string,
	googleOAuthConfig *oauth2.Config,
) ServiceInterface {
	return &Service{
		userRepo:          userRepo,
		emailer:           emailer,
		templateManager:   tm,
		jwtSecret:         JWTSecretFromConfig,
		clientOrigin:      clientOriginFromConfig,
		googleOAuthConfig: googleOAuthConfig,
	}
}

// A struct to unmarshal the Google user info response
type GoogleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

// Allows other packages (e.g., the handler) to know the frontend URL for redirects.
func (s *Service) GetClientOrigin() string {
	return s.clientOrigin
}

func (s *Service) Signup(ctx context.Context, req models.SignupRequest) (*models.User, error) {
	// 1. Check if user with that email already exists
	_, err := s.userRepo.FindByEmail(ctx, req.Email)
	if err != nil && !errors.Is(err, models.ErrNotFound) {
		// Some other database error occurred
		return nil, fmt.Errorf("service.Signup.FindByEmail: %w", err)
	}
	if err == nil {
		// User was found, email is taken
		return nil, models.ErrConflict
	}

	// 2. Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("service.Signup.HashPassword: %w", err)
	}

	// 3. Create activation token
	activationToken, err := utils.GenerateSecureToken(32)
	if err != nil {
		return nil, fmt.Errorf("service.Signup.GenerateToken: %w", err)
	}
	expiresAt := time.Now().Add(time.Minute * 30)

	// 4. Create the inactive user in the database
	newUser := &models.User{
		Nickname: req.Nickname,
		Email:    req.Email,
	}
	createdUser, err := s.userRepo.CreateInactiveUser(ctx, newUser, string(hashedPassword), activationToken, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("service.Signup.CreateUser: %w", err)
	}

	// 5. Send activation email
	activationURL := fmt.Sprintf("%s/activate?token=%s", s.clientOrigin, activationToken)

	htmlContent, err := s.templateManager.GenerateActivateAccountEmailHTML(emailSvc.TemplateData{
		Name: createdUser.Nickname,
		Link: activationURL,
	})
	if err != nil {
		// Log the error but don't fail the whole signup process
		log.Printf("Failed to generate activation email HTML: %v", err)
		return createdUser, nil
	}

	emailSubject := "Welcome! Please Activate Your Account"
	plainTextContent := fmt.Sprintf("Thank you for signing up! Please click the following link in 30 minutes to activate your account: %s", activationURL)

	go func() {
		// Run in a goroutine so it doesn't block the user's signup response
		err := s.emailer.SendEmail(context.Background(), createdUser.Email, emailSubject, plainTextContent, htmlContent)
		if err != nil {
			log.Printf("Failed to send activation email to %s: %v", createdUser.Email, err)
		}
	}()

	return createdUser, nil
}

// private helper function to generate AuthResponse
func (s *Service) generateAuthResponse(user *models.User) (*models.AuthResponse, error) {
	// 1. Create claims for JWT
	claims := &models.JwtCustomClaims{
		UserID: user.ID,
		Email:  user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24 * 30)), // 30 days expiry
		},
	}

	// 2. Create access token with claims
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// 3. Generate encoded token and send it as response
	tokenSignedString, err := accessToken.SignedString([]byte(s.jwtSecret))
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	user.PasswordHash = "" // Do NOT send sensitive info back

	return &models.AuthResponse{
		AccessToken: tokenSignedString,
		User:        user,
	}, nil
}

func (s *Service) Login(ctx context.Context, req models.LoginRequest) (*models.AuthResponse, error) {
	// 1. Find user by email
	userWithHash, err := s.userRepo.FindByEmail(ctx, req.Email) // This needs to return password hash
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, models.ErrInvalidCredentials
		}
		return nil, fmt.Errorf("service.Login.FindByEmail: %w", err)
	}

	// 2. Compare the provided password with the stored hash
	err = bcrypt.CompareHashAndPassword([]byte(userWithHash.PasswordHash), []byte(req.Password))
	if err != nil {
		// Passwords don't match
		return nil, models.ErrInvalidCredentials
	}

	// 3. Use helper function to generate JWT and AuthResponse
	return s.generateAuthResponse(userWithHash)
}

func (s *Service) ActivateUserAndLogin(ctx context.Context, token string) (*models.AuthResponse, error) {
	activatedUser, err := s.userRepo.ActivateUser(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("service.ActivateUserAndLogin: %w", err)
	}

	return s.generateAuthResponse(activatedUser)
}

func (s *Service) ResendActivationEmail(ctx context.Context, email string) error {
	// 1. Find user by email
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		// If user not found, do nothing and return nil to hide existence.
		if errors.Is(err, models.ErrNotFound) {
			log.Printf("INFO: Activation resend requested for non-existent email: %s", email)
			return nil
		}
		return fmt.Errorf("service.ResendActivationEmail.FindByEmail: %w", err)
	}

	// 2. Check if user is already active
	if user.IsActive {
		log.Printf("INFO: Activation resend requested for already active user: %s", email)
		return nil
	}

	// 3. Generate a new activation token
	activationToken, err := utils.GenerateSecureToken(32)
	if err != nil {
		return fmt.Errorf("service.ResendActivationEmail.GenerateToken: %w", err)
	}
	expiresAt := time.Now().Add(time.Minute * 30)

	// 4. Update the user record with the new token
	if err := s.userRepo.UpdateActivationToken(ctx, user.ID, activationToken, expiresAt); err != nil {
		return fmt.Errorf("service.ResendActivationEmail.UpdateToken: %w", err)
	}

	// 5. Send the new activation email
	activationURL := fmt.Sprintf("%s/activate?token=%s", s.clientOrigin, activationToken)

	htmlContent, err := s.templateManager.GenerateActivateAccountEmailHTML(emailSvc.TemplateData{
		Name: user.Nickname,
		Link: activationURL,
	})
	if err != nil {
		// Log the error but don't fail the whole signup process
		log.Printf("Failed to generate re-activation email HTML: %v", err)
		return nil
	}

	emailSubject := "Activate Your Account (New Link)"
	plainTextContent := fmt.Sprintf("Please click the following link in 30 minutes to activate your account: %s", activationURL)

	go func() {
		// Run in a goroutine so it doesn't block the user's signup response
		err := s.emailer.SendEmail(context.Background(), email, emailSubject, plainTextContent, htmlContent)
		if err != nil {
			log.Printf("Failed to send re-activation email to %s: %v", email, err)
		}
	}()

	return nil
}

func (s *Service) RequestPasswordReset(ctx context.Context, email string) error {
	// 1. Find user by email
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		// Even if user not found, return success to prevent email enumeration attacks
		log.Printf("Password reset requested for non-existent email: %s", err)
		return nil
	}

	// 2. Gnerate reset token and expiry
	token, err := utils.GenerateSecureToken(32)
	if err != nil {
		return err
	}
	expiresAt := time.Now().Add(15 * time.Minute) // token is valid for 15 minutes

	// 3. Save token and expiry to user record
	if err := s.userRepo.SetPasswordResetToken(ctx, user.ID, token, expiresAt); err != nil {
		return err
	}

	// 4. Send password reset email
	resetURL := fmt.Sprintf("%s/reset-password?token=%s", s.clientOrigin, token)

	htmlContent, err := s.templateManager.GenerateResetPasswordEmailHTML(emailSvc.TemplateData{
		Name: user.Nickname,
		Link: resetURL,
	})
	if err != nil {
		// Log the error but don't fail the whole signup process
		log.Printf("Failed to generate re-activation email HTML: %v", err)
		return nil
	}

	emailSubject := "Reset Your Password"
	plainTextContent := fmt.Sprintf("Please click the following link in 15 minutes to reset your password: %s", resetURL)

	go func() {
		// Run in a goroutine so it doesn't block the user's signup response
		err := s.emailer.SendEmail(context.Background(), email, emailSubject, plainTextContent, htmlContent)
		if err != nil {
			log.Printf("Failed to send password resetting email to %s: %v", email, err)
		}
	}()

	return nil
}

func (s *Service) ResetPassword(ctx context.Context, token string, newPassword string) (*models.AuthResponse, error) {
	// 1. Find user by reset token and check expiry
	// Read and Security Check: verify the token matches AND has not expired
	user, err := s.userRepo.FindByPasswordResetToken(ctx, token)
	if err != nil {
		return nil, models.ErrInvalidToken // Token not found or expired
	}

	// 2. Hash the new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// 3. Update the user's password and clear the reset token
	// Write and State Change: update users table in database
	if err := s.userRepo.UpdatePasswordAndClearResetToken(ctx, user.ID, string(hashedPassword)); err != nil {
		return nil, err
	}

	// 4. Log the user in by issuing a JWT
	return s.generateAuthResponse(user)
}

// HandleGoogleLogin generates and returns the redirect URL and the state value for the user.
func (s *Service) HandleGoogleLogin() (string, string, error) {
	state, err := utils.GenerateSecureToken(16)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate state for google login: %w", err)
	}
	// This generates a URL like:
	// https://accounts.google.com/o/oauth2/v2/auth?client_id=...&redirect_uri=...&response_type=code&scope=...&state=...
	url := s.googleOAuthConfig.AuthCodeURL(state)
	return url, state, nil
}

// HandleGoogleCallback processes the callback from Google, completing the login/signup.
func (s *Service) HandleGoogleCallback(ctx context.Context, code string) (*models.AuthResponse, error) {
	// 1. Exchange authorization code for a token from Google
	token, err := s.googleOAuthConfig.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("google code exchange failed: %w", err)
	}

	// 2. Use the token to get the user's info from Google's API.
	response, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info from google: %w", err)
	}
	defer response.Body.Close()

	contents, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed reading user info response body: %w", err)
	}

	var userInfo GoogleUserInfo
	if err := json.Unmarshal(contents, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user info: %w", err)
	}

	if !userInfo.VerifiedEmail {
		return nil, fmt.Errorf("google email not verified")
	}

	// 3. Find or create user in database
	user, err := s.userRepo.FindByEmail(ctx, userInfo.Email)
	if err != nil && !errors.Is(err, models.ErrNotFound) {
		return nil, fmt.Errorf("db error while finding user by email: %w", err)
	}

	if errors.Is(err, models.ErrNotFound) {
		// User does not exist, create them
		newUser := &models.User{
			Nickname:       userInfo.Name,
			Email:          userInfo.Email,
			AvatarURL:      userInfo.Picture,
			AuthProvider:   "google",
			AuthProviderID: userInfo.ID,
			IsActive:       true,
		}
		user, err = s.userRepo.CreateOAuthUser(ctx, newUser)
		if err != nil {
			return nil, err
		}
	}

	// 4. Issue JWT for this user.
	return s.generateAuthResponse(user)
}

func (s *Service) GetUserProfile(ctx context.Context, userID string) (*models.User, error) {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		// Map repository errors to service-level errors if needed
		return nil, fmt.Errorf("service.GetUserProfile: %w", err)
	}
	return user, nil
}

func (s *Service) UpdateUserProfile(ctx context.Context, userID string, data models.UserUpdateData) (*models.User, error) {
	// Check if nickname is unique if that's a requirement (would need repo method)
	if data.Nickname != nil {
		existingUserWithNickname, err := s.userRepo.FindByNickname(ctx, *data.Nickname)
		if err != nil && !errors.Is(err, models.ErrNotFound) {
			return nil, fmt.Errorf("failed to check nickname uniqueness: %w", err)
		}
		if existingUserWithNickname != nil && existingUserWithNickname.ID != userID {
			return nil, models.ErrNicknameTaken
		}
	}

	updatedUser, err := s.userRepo.Update(ctx, userID, data)
	if err != nil {
		return nil, fmt.Errorf("service.UpdateUserProfile: %w", err)
	}
	return updatedUser, nil
}

func (s *Service) ListAddresses(ctx context.Context, userID string) ([]models.Address, error) {
	allAddresses, err := s.userRepo.ListAddresses(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("service.ListAddresses: %w", err)
	}
	return allAddresses, nil
}

func (s *Service) AddAddress(ctx context.Context, userID, label, streetAddress string, isDefault bool) (*models.Address, error) {
	// If this new address is being set as the default, unset the current default.
	if isDefault {
		// This entire block should be executed in a single database transaction.
		tx, err := s.userRepo.BeginTx(ctx)
		if err != nil {
			return nil, err
		}
		// If any single operation inside the transaction fails,
		// all previous operations within the transaction should be undone.
		// As soon as starting the transaction, prepare to undo it,
		// unless Commit() is called at the end.
		defer tx.Rollback(ctx)

		// Use the transaction-aware repository to perform the operations
		txRepo := s.userRepo.WithTx(tx)

		if err := txRepo.ClearDefaultAddress(ctx, userID); err != nil {
			return nil, fmt.Errorf("failed to clear old default address: %w", err)
		}

		// Create the new address within the same transaction.
		newAddress, err := txRepo.AddAddress(ctx, userID, label, streetAddress, isDefault)
		if err != nil {
			return nil, err
		}

		if err := tx.Commit(ctx); err != nil { // Commit the transaction
			return nil, err
		}
		return newAddress, nil
	}

	// If not default, add it directly
	return s.userRepo.AddAddress(ctx, userID, label, streetAddress, isDefault)
}

func (s *Service) UpdateAddress(ctx context.Context, userID, addressID string, req models.UpdateAddressRequest) (*models.Address, error) {
	if err := s.userRepo.VerifyAddressOwner(ctx, userID, addressID); err != nil {
		return nil, fmt.Errorf("permission denied or address not found: %w", err)
	}

	// If the user wants to set this address as the default
	if req.IsDefault != nil && *req.IsDefault == true {
		tx, err := s.userRepo.BeginTx(ctx)
		if err != nil {
			return nil, err
		}
		defer tx.Rollback(ctx)

		txRepo := s.userRepo.WithTx(tx)
		if err := txRepo.ClearDefaultAddress(ctx, userID); err != nil {
			return nil, err
		}

		updatedAddress, err := txRepo.UpdateAddress(ctx, addressID, req)
		if err != nil {
			return nil, err
		}

		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return updatedAddress, nil
	}

	// Otherwise, just perform the update.
	return s.userRepo.UpdateAddress(ctx, addressID, req)
}

func (s *Service) DeleteAddress(ctx context.Context, userID, addressID string) error {
	if err := s.userRepo.VerifyAddressOwner(ctx, userID, addressID); err != nil {
		return fmt.Errorf("permission denied or address not found: %w", err)
	}

	err := s.userRepo.DeleteAddress(ctx, userID, addressID)
	if err != nil {
		return fmt.Errorf("service.DeleteAddress: %w", err)
	}
	return nil
}
