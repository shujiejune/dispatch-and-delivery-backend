package user

import (
	"dispatch-and-delivery/internal/models"
	"dispatch-and-delivery/pkg/utils"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
)

type Handler struct {
	service  ServiceInterface
	validate *validator.Validate // For request body validation
}

// NewHandler creates a new user handler.
func NewHandler(service ServiceInterface) *Handler {
	return &Handler{
		service:  service,
		validate: validator.New(),
	}
}

func (h *Handler) Signup(c echo.Context) error {
	var req models.SignupRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Invalid request body"})
	}
	if err := h.validate.Struct(req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Validation failed: " + err.Error()})
	}

	authResponse, err := h.service.Signup(c.Request().Context(), req)
	if err != nil {
		if errors.Is(err, models.ErrConflict) {
			return c.JSON(http.StatusConflict, models.ErrorResponse{Message: "Email address is already in use"})
		}
		c.Logger().Error("Handler.Signup: ", err)
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Failed to create user"})
	}

	return c.JSON(http.StatusCreated, authResponse)
}

func (h *Handler) Login(c echo.Context) error {
	var req models.LoginRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Invalid request body"})
	}
	if err := h.validate.Struct(req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Validation failed: " + err.Error()})
	}

	authResponse, err := h.service.Login(c.Request().Context(), req)
	if err != nil {
		if errors.Is(err, models.ErrInvalidCredentials) { // Define this error in models
			return c.JSON(http.StatusUnauthorized, models.ErrorResponse{Message: "Invalid email or password"})
		}
		c.Logger().Error("Handler.Login: ", err)
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Failed to log in"})
	}

	return c.JSON(http.StatusOK, authResponse)
}

// GoogleLogin initiates the Google OAuth 2.0 login flow.
// It redirects the user to Google's consent screen.
func (h *Handler) GoogleLogin(c echo.Context) error {
	// The service generates the unique URL for this login attempt.
	// This URL includes the client ID and a state parameter for security.
	authURL, state, err := h.service.HandleGoogleLogin()
	if err != nil {
		c.Logger().Error("Handler.GoogleLogin: failed to generate auth URL: ", err)
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Could not initiate Google login"})
	}

	// Create a new secure cookie to store the state parameter
	cookie := new(http.Cookie)
	cookie.Name = "oauthstate" // Name of the cookie
	cookie.Value = state
	cookie.Expires = time.Now().Add(10 * time.Minute) // Cookie is valid for 10 minutes
	cookie.Path = "/"
	cookie.HttpOnly = true // Prevents JavaScript from accessing the cookie
	cookie.Secure = true   // Only send over HTTPS (set to false in config for localhost HTTP dev)
	cookie.SameSite = http.SameSiteLaxMode
	c.SetCookie(cookie)

	// Redirect the user's browser to the Google authentication page.
	return c.Redirect(http.StatusTemporaryRedirect, authURL)
}

// GoogleCallback handles the callback request from Google after the user has authenticated,
// and validates the state parameter from the URL against the one stored in the cookie.
// Google redirects the user here with a `code` and `state` parameter in the URL.
func (h *Handler) GoogleCallback(c echo.Context) error {
	// 1. Read the state from the cookie set in the login step.
	oauthStateCookie, err := c.Cookie("oauthstate")
	if err != nil {
		// If the cookie expired or was never set
		c.Logger().Error("Handler.GoogleCallback: could not read state cookie: ", err)
		return c.JSON(http.StatusUnauthorized, models.ErrorResponse{Message: "Invalid or missing state cookie"})
	}

	// 2. Compare the state from the cookie with the state from the query parameter.
	if c.QueryParam("state") != oauthStateCookie.Value {
		c.Logger().Error("Handler.GoogleCallback: state parameter mismatch")
		return c.JSON(http.StatusUnauthorized, models.ErrorResponse{Message: "Invalid state parameter"})
	}

	// 3. Delete the cookie after it has been used once.
	oauthStateCookie.Value = ""
	oauthStateCookie.Expires = time.Unix(0, 0)
	c.SetCookie(oauthStateCookie)

	// 4. Get the authorization code from the query parameters.
	code := c.QueryParam("code")
	if code == "" {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Authorization code not provided"})
	}

	// 5. Call the service to exchange the code for a token, fetch user info,
	// find or create the user, and generate the application's JWT.
	authResponse, err := h.service.HandleGoogleCallback(c.Request().Context(), code)
	if err != nil {
		c.Logger().Error("Handler.GoogleCallback: service error: ", err)
		// Redirect to a frontend error page
		return c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/login/error", h.service.GetClientOrigin()))
	}

	// 6. Redirect the user back to a specific frontend page with the token.
	// The frontend page can then parse the token from the URL and save it.
	redirectURL := fmt.Sprintf("%s/login/success?token=%s", h.service.GetClientOrigin(), authResponse.AccessToken)
	return c.Redirect(http.StatusTemporaryRedirect, redirectURL)
}

func (h *Handler) ActivateAccount(c echo.Context) error {
	var req models.ActivationRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Invalid request: missing token"})
	}
	if err := h.validate.Struct(req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: err.Error()})
	}

	// After activation, automatically log the user in by issuing a JWT
	authResponse, err := h.service.ActivateUserAndLogin(c.Request().Context(), req.Token)
	if err != nil {
		if errors.Is(err, models.ErrInvalidToken) {
			return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Invalid or expired activation token"})
		}
		c.Logger().Error("Handler.ActivateAccount: ", err)
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Failed to activate account"})
	}

	return c.JSON(http.StatusOK, authResponse)
}

// ResendActivation handles requests to resend an activation email.
func (h *Handler) ResendActivation(c echo.Context) error {
	var req models.ResendActivationRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Invalid request: " + err.Error()})
	}
	if err := h.validate.Struct(req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Validation failed: " + err.Error()})
	}

	err := h.service.ResendActivationEmail(c.Request().Context(), req.Email)
	if err != nil {
		// Even if the service returns an error, don't expose it to the client
		// to prevent email enumeration. The error is logged in the service layer.
		c.Logger().Error("Handler.ResendActivation encountered a service error: ", err)
	}

	// Always return a generic success message to prevent attackers from discovering which emails are registered.
	return c.JSON(http.StatusOK, map[string]string{
		"message": "If an account with that email address exists and is not yet activated, a new activation link has been sent.",
	})
}

// RequestPasswordReset handles requests to initiate a password reset.
// Two-step password reset process:
// 1. User clicks "Forgot password", frontend sends a POST request to "auth/reset-password"
// 2. User submits new password on frontend page "/reset-password?token=...", frontend sends a POST request with new password
// This is the step 1
func (h *Handler) RequestPasswordReset(c echo.Context) error {
	var req models.RequestPasswordResetRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Invalid request: " + err.Error()})
	}
	if err := h.validate.Struct(req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Validation failed: " + err.Error()})
	}

	err := h.service.RequestPasswordReset(c.Request().Context(), req.Email)
	if err != nil {
		// As with activation, we log the error but don't expose it to the client.
		c.Logger().Error("Handler.RequestPasswordReset encountered a service error: ", err)
	}

	// Always return a generic success message.
	return c.JSON(http.StatusOK, map[string]string{
		"message": "If an account with that email address exists, a link to reset your password has been sent.",
	})
}

// This is the step 2
// It receives a token and a new password, validates them, and if successful,
// logs the user in by returning a new JWT.
func (h *Handler) ResetPassword(c echo.Context) error {
	// 1. Bind the incoming JSON request body to our ResetPasswordRequest struct.
	var req models.ResetPasswordRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Invalid request body: " + err.Error()})
	}

	// 2. Validate the request data using the struct tags
	if err := h.validate.Struct(req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Validation failed: " + err.Error()})
	}

	// 3. Call the corresponding service method to perform the core logic.
	// The service will verify the token, hash the new password, update the database,
	// and generate a new JWT.
	authResponse, err := h.service.ResetPassword(c.Request().Context(), req.Token, req.NewPassword)
	if err != nil {
		// 4. Handle specific errors returned from the service layer.
		if errors.Is(err, models.ErrInvalidToken) {
			// This error is returned if the token doesn't exist, is expired, or is otherwise invalid.
			return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Invalid or expired password reset token"})
		}

		// For all other unexpected errors, log them and return a generic server error.
		c.Logger().Error("Handler.ResetPassword: ", err)
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "An internal error occurred while resetting the password"})
	}

	// 5. On success, the service returns a new AuthResponse.
	return c.JSON(http.StatusOK, authResponse)
}

// --- User Profile Routes ---
func (h *Handler) GetProfile(c echo.Context) error {
	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, models.ErrorResponse{Message: err.Error()})
	}

	user, err := h.service.GetUserProfile(c.Request().Context(), userID)
	if err != nil {
		if err == models.ErrNotFound {
			return c.JSON(http.StatusNotFound, models.ErrorResponse{Message: "User profile not found"})
		}
		c.Logger().Error("Handler.GetProfile: ", err)
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Failed to retrieve profile"})
	}
	return c.JSON(http.StatusOK, user)
}

func (h *Handler) UpdateProfile(c echo.Context) error {
	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, models.ErrorResponse{Message: err.Error()})
	}

	var req models.UserUpdateData
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Invalid request body: " + err.Error()})
	}
	if err := h.validate.Struct(req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Validation failed: " + err.Error()})
	}

	user, err := h.service.UpdateUserProfile(c.Request().Context(), userID, req)
	if err != nil {
		if err == models.ErrNotFound {
			return c.JSON(http.StatusNotFound, models.ErrorResponse{Message: "User profile not found"})
		}
		c.Logger().Error("Handler.UpdateProfile: ", err)
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Failed to update profile"})
	}
	return c.JSON(http.StatusOK, user)
}

// --- User Address Routes ---
// ListAddresses retrieves all addresses for the authenticated user.
func (h *Handler) ListAddresses(c echo.Context) error {
	userID := c.Get("userID").(string)

	ctx := c.Request().Context()
	addresses, err := h.service.ListAddresses(ctx, userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: err.Error()})
	}

	return c.JSON(http.StatusOK, addresses)
}

// AddAddress creates a new address for the authenticated user.
func (h *Handler) AddAddress(c echo.Context) error {
	userID := c.Get("userID").(string)

	var req models.AddAddressRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Invalid request body"})
	}
	if err := h.validate.Struct(req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Validation failed: " + err.Error()})
	}

	ctx := c.Request().Context()
	newAddress, err := h.service.AddAddress(ctx, userID, req.Label, req.StreetAddress, req.IsDefault)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: err.Error()})
	}

	return c.JSON(http.StatusCreated, newAddress)
}

// UpdateAddress modifies an existing address for the authenticated user.
func (h *Handler) UpdateAddress(c echo.Context) error {
	userID := c.Get("userID").(string)
	addressID := c.Param("addressId")

	var req models.UpdateAddressRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Invalid request body"})
	}

	ctx := c.Request().Context()
	// The service layer will be responsible for checking that the user owns this address
	// before performing the update.
	updatedAddress, err := h.service.UpdateAddress(ctx, userID, addressID, req)
	if err != nil {
		// The service should return a specific error for not found or forbidden
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: err.Error()})
	}

	return c.JSON(http.StatusOK, updatedAddress)
}

// DeleteAddress removes an address for the authenticated user.
func (h *Handler) DeleteAddress(c echo.Context) error {
	userID := c.Get("userID").(string)
	addressID := c.Param("addressId")

	ctx := c.Request().Context()
	// The service layer will ensure the user can only delete their own address.
	err := h.service.DeleteAddress(ctx, userID, addressID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: err.Error()})
	}

	return c.NoContent(http.StatusNoContent)
}
