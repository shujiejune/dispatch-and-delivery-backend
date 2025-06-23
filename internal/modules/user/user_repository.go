package user

import (
	"context"
	"dispatch-and-delivery/internal/models"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RepositoryInterface defines methods for interacting with user storage.
type RepositoryInterface interface {
	FindByID(ctx context.Context, userID string) (*models.User, error)
	FindByEmail(ctx context.Context, email string) (*models.User, error)
	FindByNickname(ctx context.Context, nickname string) (*models.User, error)
	FindByPasswordResetToken(ctx context.Context, token string) (*models.User, error)

	SetPasswordResetToken(ctx context.Context, userID string, token string, expiresAt time.Time) error
	UpdatePasswordAndClearResetToken(ctx context.Context, userID string, passwordHash string) error
	UpdateActivationToken(ctx context.Context, userID, newToken string, expiresAt time.Time) error

	CreateInactiveUser(ctx context.Context, user *models.User, passwordHash, activationToken string, expiresAt time.Time) (*models.User, error)
	ActivateUser(ctx context.Context, token string) (*models.User, error)
	CreateOAuthUser(ctx context.Context, user *models.User) (*models.User, error) // Assuming you might add direct user creation
	Update(ctx context.Context, userID string, updateData models.UserUpdateData) (*models.User, error)
}

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) RepositoryInterface {
	return &Repository{db: db}
}

func (r *Repository) FindByID(ctx context.Context, userID string) (*models.User, error) {
	user := &models.User{}
	query := `SELECT id, nickname, email, avatar_url, auth_provider, is_active, created_at, updated_at FROM users WHERE id = $1`
	err := r.db.QueryRow(ctx, query, userID).Scan(
		&user.ID, &user.Nickname, &user.Email, &user.AvatarURL, &user.AuthProvider, &user.IsActive, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, models.ErrNotFound
		}
		return nil, fmt.Errorf("repository.FindByID: %w", err)
	}
	return user, nil
}

func (r *Repository) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	// Similar to FindByID, but queries by email
	// Important for checking if email exists during signup if you implement it
	user := &models.User{}
	query := `SELECT id, nickname, email, password_hash, avatar_url, auth_provider, is_active, created_at, updated_at FROM users WHERE email = $1`
	err := r.db.QueryRow(ctx, query, email).Scan(
		&user.ID, &user.Nickname, &user.Email, &user.PasswordHash, &user.AvatarURL, &user.AuthProvider, &user.IsActive, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, models.ErrNotFound
		}
		return nil, fmt.Errorf("repository.FindByEmail: %w", err)
	}
	return user, nil
}

func (r *Repository) FindByNickname(ctx context.Context, nickname string) (*models.User, error) {
	user := &models.User{}
	query := `SELECT id, nickname, email, avatar_url, auth_provider, is_active, created_at, updated_at FROM users WHERE nickname = $1`
	err := r.db.QueryRow(ctx, query, nickname).Scan(
		&user.ID, &user.Nickname, &user.Email, &user.AvatarURL, &user.AuthProvider, &user.IsActive, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, models.ErrNotFound
		}
		return nil, fmt.Errorf("repository.FindByNickname: %w", err)
	}
	return user, nil
}

func (r *Repository) FindByPasswordResetToken(ctx context.Context, token string) (*models.User, error) {
	user := &models.User{}

	query := `
	SELECT id, nickname, email, password_hash, avatar_url, auth_provider, auth_provider_id, is_active, created_at, updated_at
	FROM users
	WHERE password_reset_token = $1 AND password_reset_expires_at > NOW()
	`

	err := r.db.QueryRow(ctx, query, token).Scan(
		&user.ID, &user.Nickname, &user.Email, &user.AvatarURL, &user.CreatedAt, &user.UpdatedAt, &user.IsActive,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, models.ErrInvalidToken
		}
		return nil, fmt.Errorf("repository.FindUserByPasswordResetToken: %w", err)
	}
	return user, nil
}

func (r *Repository) SetPasswordResetToken(ctx context.Context, userID string, token string, expiresAt time.Time) error {
	query := `
	UPDATE users
	SET password_reset_token = $1, password_reset_expires_at = $2, updated_at = NOW()
	WHERE id = $3
	`
	cmdTag, err := r.db.Exec(ctx, query, token, expiresAt, userID)
	if err != nil {
		return fmt.Errorf("repository.SetPasswordResetToken: %w", err)
	}
	if cmdTag.RowsAffected() == 0 {
		return models.ErrNotFound // userID not found, no update to password_reset_token
	}

	return nil
}

func (r *Repository) UpdatePasswordAndClearResetToken(ctx context.Context, userID string, passwordHash string) error {
	query := `
	UPDATE users
	SET password_hash = $1, password_reset_token = $2, updated_at = NOW()
	WHERE id = $3
	`
	cmdTag, err := r.db.Exec(ctx, query, passwordHash, "", userID)
	if err != nil {
		return fmt.Errorf("repository.UpdatePasswordAndClearResetToken: %w", err)
	}
	if cmdTag.RowsAffected() == 0 {
		return models.ErrNotFound // userID not found, no update to password_hash
	}

	return nil
}

func (r *Repository) UpdateActivationToken(ctx context.Context, userID, newToken string, expiresAt time.Time) error {
	query := `
	UPDATE users
	SET activation_token = $1, activation_token_expires_at = $2, updated_at = NOW()
	WHERE id = $3
	`
	cmdTag, err := r.db.Exec(ctx, query, newToken, expiresAt, userID)
	if err != nil {
		return fmt.Errorf("repository.UpdateActivationToken: %w", err)
	}
	if cmdTag.RowsAffected() == 0 {
		return models.ErrNotFound // userID not found, no update to activation_token
	}

	return nil
}

// Specifically for the email/password signup flow
func (r *Repository) CreateInactiveUser(ctx context.Context, user *models.User, passwordHash, activationToken string, expiresAt time.Time) (*models.User, error) {
	query := `
        INSERT INTO users (nickname, email, password_hash, activation_token, activation_token_expires_at, auth_provider)
        VALUES ($1, $2, $3, $4, $5, $6, 'email')
        RETURNING id, created_at, updated_at`
	err := r.db.QueryRow(ctx, query,
		user.Nickname, user.Email, passwordHash, activationToken, expiresAt,
	).Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("repository.CreateInactiveUser: %w", err)
	}
	return user, err
}

func (r *Repository) ActivateUser(ctx context.Context, token string) (*models.User, error) {
	// Find user by token, set is_active = true, and clear the token
	var user models.User
	query := `
        UPDATE users
        SET is_active = TRUE, activation_token = NULL, activation_token_expires_at = NULL, updated_at = NOW()
        WHERE activation_token = $1 AND activation_token_expires_at > NOW() AND is_active = FALSE
        RETURNING id, nickname, email, avatar_url, auth_provider, is_active, created_at, updated_at`
	err := r.db.QueryRow(ctx, query, token).Scan(&user.ID, &user.Nickname, &user.Email, &user.AvatarURL, &user.AuthProvider, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, models.ErrInvalidToken
		}
		return nil, fmt.Errorf("repository.ActivateUser: %w", err)
	}
	return &user, nil
}

// Specifically for OAuth signup flow (Google/WeChat)
func (r *Repository) CreateOAuthUser(ctx context.Context, user *models.User) (*models.User, error) {
	query := `
        INSERT INTO users (nickname, email, auth_provider, auth_provider_id, is_active)
        VALUES ($1, $2, $3, $4, $5, TRUE)
        RETURNING id, created_at, updated_at`
	err := r.db.QueryRow(ctx, query,
		user.Nickname, user.Email, user.AuthProvider, user.AuthProviderID,
	).Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		// Handle potential duplicate email error (unique constraint)
		return nil, fmt.Errorf("repository.CreateOAuthUser: %w", err)
	}
	return user, nil
}

func (r *Repository) Update(ctx context.Context, userID string, data models.UserUpdateData) (*models.User, error) {
	// Build query dynamically based on fields provided in UserUpdateData
	// For simplicity, let's assume nickname and avatar_url are updatable
	var setClauses []string
	var args []interface{}
	argIdx := 1

	if data.Nickname != nil {
		setClauses = append(setClauses, fmt.Sprintf("nickname = $%d", argIdx))
		args = append(args, *data.Nickname)
		argIdx++
	}
	if data.AvatarURL != nil {
		setClauses = append(setClauses, fmt.Sprintf("avatar_url = $%d", argIdx))
		args = append(args, *data.AvatarURL)
		argIdx++
	}

	if len(setClauses) == 0 {
		return r.FindByID(ctx, userID) // No fields to update, return current user
	}

	setClauses = append(setClauses, fmt.Sprintf("updated_at = $%d", argIdx))
	args = append(args, time.Now())
	argIdx++

	args = append(args, userID) // For WHERE clause

	query := fmt.Sprintf(`UPDATE users SET %s WHERE id = $%d RETURNING id, nickname, email, avatar_url, created_at, updated_at`,
		strings.Join(setClauses, ", "), argIdx)

	updatedUser := &models.User{}
	err := r.db.QueryRow(ctx, query, args...).Scan(
		&updatedUser.ID, &updatedUser.Nickname, &updatedUser.Email, &updatedUser.PasswordHash, &updatedUser.AvatarURL, &updatedUser.AuthProvider, &updatedUser.AuthProviderID, &updatedUser.IsActive, &updatedUser.CreatedAt, &updatedUser.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("repository.UpdateUser: %w", err)
	}
	return updatedUser, nil
}
