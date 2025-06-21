package user

import (
	"errors"
	"fmt"
	"jingdezhen-ceramics-backend/internal/models"
	"jingdezhen-ceramics-backend/pkg/utils"
	"net/http"
	"strconv"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
)

type Handler struct {
	service  ServiceInterface
	validate *validator.Validate // For request body validation
}

// NewHandler creates a new user handler.
// The AdminHandler can be this same handler, with routes protected by AdminRequired middleware.
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
	authURL, err := h.service.HandleGoogleLogin()
	if err != nil {
		c.Logger().Error("Handler.GoogleLogin: failed to generate auth URL: ", err)
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Could not initiate Google login"})
	}

	// Redirect the user's browser to the Google authentication page.
	return c.Redirect(http.StatusTemporaryRedirect, authURL)
}

// GoogleCallback handles the callback request from Google after the user has authenticated.
// Google redirects the user here with a `code` and `state` parameter in the URL.
func (h *Handler) GoogleCallback(c echo.Context) error {
	// For a production app, you must validate the `state` parameter here against a value
	// stored in the user's session/cookie to prevent CSRF attacks. We'll omit for simplicity.
	if c.QueryParam("state") != storedState {
		return c.JSON(http.StatusUnauthorized, models.ErrorResponse{Message: "Invalid state"})
	}

	// Get the authorization code from the query parameters.
	code := c.QueryParam("code")
	if code == "" {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Authorization code not provided"})
	}

	// Call the service to exchange the code for a token, fetch user info,
	// find or create the user, and generate our application's JWT.
	authResponse, err := h.service.HandleGoogleCallback(c.Request().Context(), code)
	if err != nil {
		c.Logger().Error("Handler.GoogleCallback: service error: ", err)
		// Redirect to a frontend error page
		return c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/login/error", h.service.GetFrontendDomain()))
	}

	// On success, we need to get the JWT to the frontend.
	// A common way is to redirect the user back to a specific frontend page
	// and include the token as a query parameter.
	// The frontend page can then parse the token from the URL and save it.
	redirectURL := fmt.Sprintf("%s/login/success?token=%s", h.service.ClientOrigin, authResponse.AccessToken)
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

func (h *Handler) SubmitContactForm(c echo.Context) error {
	var req models.ContactFormData
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Invalid request body: " + err.Error()})
	}
	if err := h.validate.Struct(req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Validation failed: " + err.Error()})
	}

	err := h.service.HandleContactSubmission(c.Request().Context(), req)
	if err != nil {
		c.Logger().Error("Handler.SubmitContactForm: ", err)
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Failed to submit contact form"})
	}
	return c.JSON(http.StatusOK, map[string]string{"message": "Contact form submitted successfully"})
}

// --- User Notes Routes (within /profile group) ---
func (h *Handler) GetUserNotes(c echo.Context) error {
	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, models.ErrorResponse{Message: err.Error()})
	}

	page, limit := utils.GetPageLimit(c)
	notes, total, err := h.service.ListUserNotes(c.Request().Context(), userID, page, limit)
	if err != nil {
		c.Logger().Error("Handler.GetUserNotes: ", err)
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Failed to retrieve notes"})
	}
	return c.JSON(http.StatusOK, models.NewPaginatedResponse(notes, page, limit, total))
}

func (h *Handler) CreateUserNote(c echo.Context) error {
	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, models.ErrorResponse{Message: err.Error()})
	}

	var req models.CreateUserNoteData
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Invalid request: " + err.Error()})
	}
	if err := h.validate.Struct(req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Validation failed: " + err.Error()})
	}

	note, err := h.service.CreateUserNote(c.Request().Context(), userID, req)
	if err != nil {
		c.Logger().Error("Handler.CreateUserNote: ", err)
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Failed to create note"})
	}
	return c.JSON(http.StatusCreated, note)
}

func (h *Handler) UpdateUserNote(c echo.Context) error {
	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, models.ErrorResponse{Message: err.Error()})
	}
	noteID, err := strconv.Atoi(c.Param("note_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Invalid note ID"})
	}

	var req models.UpdateUserNoteData
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Invalid request: " + err.Error()})
	}
	if err := h.validate.Struct(req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Validation failed: " + err.Error()})
	}

	note, err := h.service.UpdateUserNote(c.Request().Context(), userID, noteID, req)
	if err != nil {
		if err == models.ErrNotFound {
			return c.JSON(http.StatusNotFound, models.ErrorResponse{Message: "Note not found or not owned by user"})
		}
		c.Logger().Error("Handler.UpdateUserNote: ", err)
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Failed to update note"})
	}
	return c.JSON(http.StatusOK, note)
}

func (h *Handler) DeleteUserNote(c echo.Context) error {
	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, models.ErrorResponse{Message: err.Error()})
	}
	noteID, err := strconv.Atoi(c.Param("note_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Invalid note ID"})
	}

	err = h.service.DeleteUserNote(c.Request().Context(), userID, noteID)
	if err != nil {
		if err == models.ErrNotFound {
			return c.JSON(http.StatusNotFound, models.ErrorResponse{Message: "Note not found or not owned by user"})
		}
		c.Logger().Error("Handler.DeleteUserNote: ", err)
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Failed to delete note"})
	}
	return c.NoContent(http.StatusNoContent)
}

func (h *Handler) AddLinkToNote(c echo.Context) error {
	noteID, err := strconv.Atoi(c.Param("note_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Invalid note ID"})
	}

	var req models.AddLinkToNoteData
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Invalid request: " + err.Error()})
	}
	if err := h.validate.Struct(req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Validation failed: " + err.Error()})
	}

	note, err := h.service.AddLinkToNote(c.Request().Context(), noteID, req)
	if err != nil {
		c.Logger().Error("Handler.AddLinkToNote: ", err)
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Failed to add link to note"})
	}
	return c.JSON(http.StatusCreated, note)
}

func (h *Handler) RemoveLinkFromNote(c echo.Context) error {
	noteID, err := strconv.Atoi(c.Param("note_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Invalid note ID"})
	}
	linkID, err := strconv.Atoi(c.Param("link_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Invalid note ID"})
	}

	err = h.service.RemoveLinkFromNote(c.Request().Context(), noteID, linkID)
	if err != nil {
		if err == models.ErrNotFound {
			return c.JSON(http.StatusNotFound, models.ErrorResponse{Message: "Link not found"})
		}
		c.Logger().Error("Handler.RemoveLinkFromNote: ", err)
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Failed to remove link from note"})
	}
	return c.NoContent(http.StatusNoContent)
}

func (h *Handler) PublishNoteToForum(c echo.Context) error {
	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, models.ErrorResponse{Message: err.Error()})
	}
	noteID, err := strconv.Atoi(c.Param("note_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Invalid note ID"})
	}

	var req models.ForumPostPublishDetails
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Invalid request: " + err.Error()})
	}
	if err := h.validate.Struct(req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Validation failed: " + err.Error()})
	}

	forumPost, err := h.service.PublishNoteToForum(c.Request().Context(), userID, noteID, req)
	if err != nil {
		if err == models.ErrNotFound {
			return c.JSON(http.StatusNotFound, models.ErrorResponse{Message: "Note not found or not owned by user"})
		}
		if err == models.ErrConflict {
			return c.JSON(http.StatusConflict, models.ErrorResponse{Message: "Note already published"})
		}
		c.Logger().Error("Handler.PublishNoteToForum: ", err)
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Failed to publish note to forum"})
	}
	return c.JSON(http.StatusCreated, forumPost)
}

// GetNotifications would be similar to GetUserNotes, fetching from a notification service/repo
func (h *Handler) GetNotifications(c echo.Context) error {
	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, models.ErrorResponse{Message: err.Error()})
	}

	page, limit := utils.GetPageLimit(c)
	notifications, total, err := h.service.GetNotifications(c.Request().Context(), userID, page, limit)
	if err != nil {
		c.Logger().Error("Handler.GetNotifications: ", err)
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Failed to retrieve notifications"})
	}
	return c.JSON(http.StatusOK, models.NewPaginatedResponse(notifications, page, limit, total))
}

// GetFavoriteArtworks - requires gallery service/repo interaction
func (h *Handler) GetFavoriteArtworks(c echo.Context) error {
	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, models.ErrorResponse{Message: err.Error()})
	}

	page, limit := utils.GetPageLimit(c)
	favArtworks, total, err := h.service.GetFavArtworks(c.Request().Context(), userID, page, limit)
	if err != nil {
		c.Logger().Error("Handler.GetFavArtworks: ", err)
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Failed to retrieve favorite artworks"})
	}
	return c.JSON(http.StatusOK, models.NewPaginatedResponse(favArtworks, page, limit, total))
}

// GetSavedForumPosts - requires forum service/repo interaction
func (h *Handler) GetSavedForumPosts(c echo.Context) error {
	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, models.ErrorResponse{Message: err.Error()})
	}

	page, limit := utils.GetPageLimit(c)
	savedForumPosts, total, err := h.service.GetSavedForumPosts(c.Request().Context(), userID, page, limit)
	if err != nil {
		c.Logger().Error("Handler.GetSavedForumPosts: ", err)
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Failed to retrieve saved forum posts"})
	}
	return c.JSON(http.StatusOK, models.NewPaginatedResponse(savedForumPosts, page, limit, total))
}

// --- Admin User Management Routes ---
// These methods are part of the same *user.Handler but will be protected by AdminRequired middleware in router.go
func (h *Handler) AdminListUsers(c echo.Context) error {
	page, limit := utils.GetPageLimit(c)
	users, total, err := h.service.AdminListUsers(c.Request().Context(), page, limit)
	if err != nil {
		c.Logger().Error("Handler.AdminListUsers: ", err)
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Failed to list users"})
	}
	return c.JSON(http.StatusOK, models.NewPaginatedResponse(users, page, limit, total))
}

func (h *Handler) AdminUpdateUserRole(c echo.Context) error {
	targetUserID := c.Param("user_id")
	var req struct {
		Role string `json:"role" validate:"required,oneof=admin normal_user"`
	}
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Invalid request body: " + err.Error()})
	}
	if err := h.validate.Struct(req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Validation failed: " + err.Error()})
	}

	err := h.service.AdminUpdateUserRole(c.Request().Context(), targetUserID, req.Role)
	if err != nil {
		if err == models.ErrNotFound {
			return c.JSON(http.StatusNotFound, models.ErrorResponse{Message: "Target user not found"})
		}
		c.Logger().Error("Handler.AdminUpdateUserRole: ", err)
		// Check for specific service errors if any (e.g., invalid role error from service)
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Failed to update user role"})
	}
	return c.JSON(http.StatusOK, map[string]string{"message": "User role updated successfully"})
}
