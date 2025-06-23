package models

import "time" // if you have CreatedAt, UpdatedAt

// Role constants for user roles
const (
	RoleAdmin      = "admin"
	RoleNormalUser = "normal_user"
	RoleGuest      = "guest" // Though guest is usually implied by lack of auth
)

type ProfileData struct {
	HeatmapData  map[string]int `json:"heatmap_data,omitempty"`
	BadgeIDs     []int          `json:"badge_ids,omitempty"`
	OtherContact string         `json:"other_contact,omitempty"`
}

// User struct (you'll have more fields from your DB schema)
type User struct {
	ID             string       `json:"id" db:"id"` // UUID string from DB
	Nickname       string       `json:"nickname,omitempty" db:"nickname"`
	Email          string       `json:"email" db:"email"`
	PasswordHash   string       `json:"-" db:"password_hash"`
	Role           string       `json:"role" db:"role"`
	AvatarURL      string       `json:"avatar_url,omitempty" db:"avatar_url"`
	ProfileData    *ProfileData `json:"profile_data,omitempty" db:"profile_data"`
	AuthProvider   string       `json:"auth_provider" db:"auth_provider"`
	AuthProviderID string       `json:"-" db:"auth_provider_id"`
	IsActive       bool         `json:"is_active" db:"is_active"`
	CreatedAt      time.Time    `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at" db:"updated_at"`
	// Add other fields as per your DB schema
}

type SignupRequest struct {
	Nickname string `json:"nickname" validate:"required,min=2,max=50"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type ActivationRequest struct {
	Token string `json:"token" validate:"required"`
}

type AuthResponse struct {
	AccessToken string `json:"access_token"`
	User        *User  `json:"user"`
}

// UserUpdateData defines fields that can be updated for a user profile
type UserUpdateData struct {
	Nickname     *string `json:"nickname,omitempty" validate:"omitempty,min=1,max=100"`
	AvatarURL    *string `json:"avatar_url,omitempty" validate:"omitempty,url"`
	OtherContact *string `json:"other_contact,omitempty" validate:"omitempty,max=255"`
	// Add other updatable fields like contacts from profile_data if needed
}

// UserWithPasswordHash is used internally when password hash is needed
type UserWithPasswordHash struct {
	User
	PasswordHash string `db:"password_hash"`
}

// ResendActivationRequest defines the body for the resend activation email request.
type ResendActivationRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// RequestPasswordResetRequest defines the body for the request password reset endpoint.
type RequestPasswordResetRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// ResetPasswordRequest defines the body for completing the password reset.
type ResetPasswordRequest struct {
	Token       string `json:"token" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8"` // Enforce a minimum password length
}
