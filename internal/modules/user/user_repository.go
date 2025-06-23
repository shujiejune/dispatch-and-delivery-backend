package user

import (
	"context"
	"dispatch-and-delivery/internal/models"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RepositoryInterface defines methods for interacting with user storage.
type RepositoryInterface interface {
	BeginTx(ctx context.Context) (pgx.Tx, error)
	WithTx(tx pgx.Tx) *Repository

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

	ClearDefaultAddress(ctx context.Context, userID string) error
	VerifyAddressOwner(ctx context.Context, userID, addressID string) error
	ListAddresses(ctx context.Context, userID string) ([]models.Address, error)
	AddAddress(ctx context.Context, userID, label, streetAddress string, isDefault bool) (*models.Address, error)
	UpdateAddress(ctx context.Context, addressID string, req models.UpdateAddressRequest) (*models.Address, error)
	DeleteAddress(ctx context.Context, userID, addressID string) error
}

// This interface represents anything that can execute a SQL query,
// which includes both a connection pool and a transaction.
type DBExecutor interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type Repository struct {
	db       *pgxpool.Pool
	executor DBExecutor
}

func NewRepository(db *pgxpool.Pool) RepositoryInterface {
	return &Repository{
		db:       db,
		executor: db,
	}
}

// BeginTx starts a new database transaction.
func (r *Repository) BeginTx(ctx context.Context) (pgx.Tx, error) {
	return r.db.Begin(ctx)
}

// WithTx returns a new instance of the Repository that is "scoped" to the provided transaction.
// All database operations on the returned repository will be part of this single transaction.
func (r *Repository) WithTx(tx pgx.Tx) *Repository {
	return &Repository{
		db:       r.db,
		executor: tx, // The executor is now the transaction, not the pool
	}
}

func (r *Repository) FindByID(ctx context.Context, userID string) (*models.User, error) {
	user := &models.User{}
	query := `SELECT id, nickname, email, avatar_url, auth_provider, is_active, created_at, updated_at FROM users WHERE id = $1`
	err := r.executor.QueryRow(ctx, query, userID).Scan(
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
	err := r.executor.QueryRow(ctx, query, email).Scan(
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
	err := r.executor.QueryRow(ctx, query, nickname).Scan(
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

	err := r.executor.QueryRow(ctx, query, token).Scan(
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
	cmdTag, err := r.executor.Exec(ctx, query, token, expiresAt, userID)
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
	cmdTag, err := r.executor.Exec(ctx, query, passwordHash, "", userID)
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
	cmdTag, err := r.executor.Exec(ctx, query, newToken, expiresAt, userID)
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
	err := r.executor.QueryRow(ctx, query,
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
	err := r.executor.QueryRow(ctx, query, token).Scan(&user.ID, &user.Nickname, &user.Email, &user.AvatarURL, &user.AuthProvider, &user.CreatedAt, &user.UpdatedAt)
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
	err := r.executor.QueryRow(ctx, query,
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
	err := r.executor.QueryRow(ctx, query, args...).Scan(
		&updatedUser.ID, &updatedUser.Nickname, &updatedUser.Email, &updatedUser.PasswordHash, &updatedUser.AvatarURL, &updatedUser.AuthProvider, &updatedUser.AuthProviderID, &updatedUser.IsActive, &updatedUser.CreatedAt, &updatedUser.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("repository.UpdateUser: %w", err)
	}
	return updatedUser, nil
}

// ClearDefaultAddress sets is_default to false for all of a user's addresses.
func (r *Repository) ClearDefaultAddress(ctx context.Context, userID string) error {
	query := `UPDATE addresses SET is_default = false WHERE user_id = $1 AND is_default = true;`

	_, err := r.executor.Exec(ctx, query, userID)
	return err
}

// VerifyAddressOwner checks if a given addressID belongs to the userID.
func (r *Repository) VerifyAddressOwner(ctx context.Context, userID, addressID string) error {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM addresses WHERE id = $1 AND user_id = $2);`
	err := r.executor.QueryRow(ctx, query, addressID, userID).Scan(&exists)
	if err != nil {
		return err
	}
	if !exists {
		// Use a standard error type for "not found"
		return pgx.ErrNoRows
	}
	return nil
}

func (r *Repository) ListAddresses(ctx context.Context, userID string) ([]models.Address, error) {
	var addresses []models.Address

	query := `
	SELECT id, user_id, label, street_address, is_default, created_at, updated_at 
	FROM addresses
	WHERE user_id = $1
	`
	rows, err := r.executor.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("repository.ListAddresses: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var addr models.Address
		if err := rows.Scan(&addr.ID, &addr.UserID, &addr.Label, &addr.StreetAddress, &addr.IsDefault, &addr.CreatedAt, &addr.UpdatedAt); err != nil {
			return nil, fmt.Errorf("repository.ListAddresses.Scan: %w", err)
		}
		addresses = append(addresses, addr)
	}

	return addresses, nil
}

// AddAddress creates a new address record. It will run within a transaction if the repository was created using WithTx().
func (r *Repository) AddAddress(ctx context.Context, userID, label, streetAddress string, isDefault bool) (*models.Address, error) {
	query := `
        INSERT INTO addresses (user_id, label, street_address, is_default)
        VALUES ($1, $2, $3, $4)
        RETURNING id, user_id, label, street_address, is_default, created_at, updated_at;
	`
	var addr models.Address
	row := r.executor.QueryRow(ctx, query, userID, label, streetAddress, isDefault)
	err := row.Scan(&addr.ID, &addr.UserID, &addr.Label, &addr.StreetAddress, &addr.IsDefault, &addr.CreatedAt, &addr.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &addr, nil
}

func (r *Repository) UpdateAddress(ctx context.Context, addressID string, req models.UpdateAddressRequest) (*models.Address, error) {
	var setClauses []string
	var args []interface{}
	argCount := 1

	// Dynamically build the SET part of the query based on which fields are provided.
	if req.Label != "" {
		setClauses = append(setClauses, fmt.Sprintf("label = $%d", argCount))
		args = append(args, req.Label)
		argCount++
	}
	if req.StreetAddress != "" {
		setClauses = append(setClauses, fmt.Sprintf("street_address = $%d", argCount))
		args = append(args, req.StreetAddress)
		argCount++
	}
	if req.IsDefault != nil { // Check the pointer, not the value
		setClauses = append(setClauses, fmt.Sprintf("is_default = $%d", argCount))
		args = append(args, *req.IsDefault)
		argCount++
	}

	// If no fields were provided to update, we can return early.
	if len(setClauses) == 0 {
		return nil, fmt.Errorf("no fields to update")
	}

	// Always update the updated_at timestamp
	setClauses = append(setClauses, fmt.Sprintf("updated_at = $%d", argCount))
	args = append(args, "now()")
	argCount++

	args = append(args, addressID)

	query := fmt.Sprintf(`
        UPDATE addresses
        SET %s
        WHERE id = $%d
        RETURNING id, user_id, label, street_address, is_default, created_at, updated_at;
	`, strings.Join(setClauses, ", "), argCount)

	var addr models.Address
	row := r.executor.QueryRow(ctx, query, args...)
	err := row.Scan(&addr.ID, &addr.UserID, &addr.Label, &addr.StreetAddress, &addr.IsDefault, &addr.CreatedAt, &addr.UpdatedAt)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, models.ErrNotFound
		}
		return nil, fmt.Errorf("repository.UpdateAddress: %w", err)
	}

	return &addr, nil
}

func (r *Repository) DeleteAddress(ctx context.Context, userID, addressID string) error {
	query := `DELETE FROM addresses WHERE id = $1 AND user_id = $2`
	cmdTag, err := r.executor.Exec(ctx, query, addressID, userID)
	if err != nil {
		return fmt.Errorf("repository.DeleteAddress: %w", err)
	}
	if cmdTag.RowsAffected() == 0 {
		return models.ErrNotFound
	}
	return nil
}
