package user

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"jingdezhen-ceramics-backend/internal/models"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	// "github.com/Masterminds/squirrel" // Optional: for SQL query building
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
	ListAll(ctx context.Context, page, limit int) ([]models.User, int, error) // For admin: list users
	UpdateRole(ctx context.Context, userID string, newRole string) error      // For admin: update role

	// User Notes specific methods
	GetUserNoteByID(ctx context.Context, noteID int, userID string) (*models.UserNote, error)
	GetLinksForNote(ctx context.Context, noteID int) ([]models.UserNoteLink, error)
	ListUserNotes(ctx context.Context, userID string, page, limit int) ([]models.UserNote, int, error)
	CreateUserNote(ctx context.Context, userID string, data models.CreateUserNoteData) (*models.UserNote, error)
	UpdateUserNote(ctx context.Context, noteID int, userID string, data models.UpdateUserNoteData) (*models.UserNote, error)
	DeleteUserNote(ctx context.Context, noteID int, userID string) error
	AddLinkToNote(ctx context.Context, noteID int, data models.AddLinkToNoteData) (*models.UserNoteLink, error)
	RemoveLinkFromNote(ctx context.Context, noteID, linkID int) error
	MarkNoteAsPublished(ctx context.Context, noteID int, forumPostID int) error

	// Other profile data
	GetNotifications(ctx context.Context, userID string, page, limit int) ([]models.Notification, int, error)
	GetFavArtworks(ctx context.Context, userID string, page, limit int) ([]models.UserFavArtworkEntry, int, error)
	GetSavedForumPosts(ctx context.Context, userID string, page, limit int) ([]models.UserSavedPostEntry, int, error)
}

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) RepositoryInterface {
	return &Repository{db: db}
}

func (r *Repository) FindByID(ctx context.Context, userID string) (*models.User, error) {
	user := &models.User{}
	query := `SELECT id, nickname, email, role, avatar_url, profile_data, auth_provider, is_active, created_at, updated_at FROM users WHERE id = $1`
	err := r.db.QueryRow(ctx, query, userID).Scan(
		&user.ID, &user.Nickname, &user.Email, &user.Role, &user.AvatarURL, &user.ProfileData, &user.AuthProvider, &user.IsActive, &user.CreatedAt, &user.UpdatedAt,
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
	query := `SELECT id, nickname, email, password_hash, role, avatar_url, profile_data, auth_provider, is_active, created_at, updated_at FROM users WHERE email = $1`
	err := r.db.QueryRow(ctx, query, email).Scan(
		&user.ID, &user.Nickname, &user.Email, &user.PasswordHash, &user.Role, &user.AvatarURL, &user.ProfileData, &user.AuthProvider, &user.IsActive, &user.CreatedAt, &user.UpdatedAt,
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
	query := `SELECT id, nickname, email, role, avatar_url, profile_data, auth_provider, is_active, created_at, updated_at FROM users WHERE nickname = $1`
	err := r.db.QueryRow(ctx, query, nickname).Scan(
		&user.ID, &user.Nickname, &user.Email, &user.Role, &user.AvatarURL, &user.ProfileData, &user.AuthProvider, &user.IsActive, &user.CreatedAt, &user.UpdatedAt,
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
	SELECT id, nickname, email, password_hash, role, avatar_url, profile_data, auth_provider, auth_provider_id, is_active, created_at, updated_at
	FROM users
	WHERE password_reset_token = $1 AND password_reset_expires_at > NOW()
	`

	err := r.db.QueryRow(ctx, query, token).Scan(
		&user.ID, &user.Nickname, &user.Email, &user.Role, &user.AvatarURL, &user.CreatedAt, &user.UpdatedAt, &user.IsActive,
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
		return models.ErrNotFound // userID not found, no update to password_reset_token
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
		return models.ErrNotFound // userID not found, no update to password_reset_token
	}

	return nil
}

// Specifically for the email/password signup flow
func (r *Repository) CreateInactiveUser(ctx context.Context, user *models.User, passwordHash, activationToken string, expiresAt time.Time) (*models.User, error) {
	query := `
        INSERT INTO users (nickname, email, password_hash, role, activation_token, activation_token_expires_at, auth_provider)
        VALUES ($1, $2, $3, $4, $5, $6, 'email')
        RETURNING id, created_at, updated_at`
	err := r.db.QueryRow(ctx, query,
		user.Nickname, user.Email, passwordHash, user.Role, activationToken, expiresAt,
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
        RETURNING id, nickname, email, role, avatar_url, profile_data, auth_provider, is_active, created_at, updated_at`
	err := r.db.QueryRow(ctx, query, token).Scan(&user.ID, &user.Nickname, &user.Email, &user.Role, &user.AvatarURL, &user.ProfileData, &user.AuthProvider, &user.CreatedAt, &user.UpdatedAt)
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
        INSERT INTO users (nickname, email, role, auth_provider, auth_provider_id, is_active)
        VALUES ($1, $2, $3, $4, $5, TRUE)
        RETURNING id, created_at, updated_at`
	err := r.db.QueryRow(ctx, query,
		user.Nickname, user.Email, user.Role, user.AuthProvider, user.AuthProviderID,
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
	if data.OtherContact != nil {
		setClauses = append(setClauses, fmt.Sprintf("profile_data = jsonb_set(COALESCE(profile_data, '{}'::jsonb), '{other_contact}', $%d::jsonb)", argIdx))
		args = append(args, *data.OtherContact)
		argIdx++
	}

	if len(setClauses) == 0 {
		return r.FindByID(ctx, userID) // No fields to update, return current user
	}

	setClauses = append(setClauses, fmt.Sprintf("updated_at = $%d", argIdx))
	args = append(args, time.Now())
	argIdx++

	args = append(args, userID) // For WHERE clause

	query := fmt.Sprintf(`UPDATE users SET %s WHERE id = $%d RETURNING id, nickname, email, role, avatar_url, created_at, updated_at`,
		strings.Join(setClauses, ", "), argIdx)

	updatedUser := &models.User{}
	err := r.db.QueryRow(ctx, query, args...).Scan(
		&updatedUser.ID, &updatedUser.Nickname, &updatedUser.Email, &updatedUser.PasswordHash, &updatedUser.Role, &updatedUser.AvatarURL, &updatedUser.ProfileData, &updatedUser.AuthProvider, &updatedUser.AuthProviderID, &updatedUser.IsActive, &updatedUser.CreatedAt, &updatedUser.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("repository.UpdateUser: %w", err)
	}
	return updatedUser, nil
}

// --- Admin specific methods ---
func (r *Repository) ListAll(ctx context.Context, page, limit int) ([]models.User, int, error) {
	offset := (page - 1) * limit
	query := `SELECT id, nickname, email, password_hash, role, avatar_url, profile_data, auth_provider, auth_provider_id, is_active, created_at, updated_at FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2`
	rows, err := r.db.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("repository.ListAllUsers: %w", err)
	}
	defer rows.Close()

	users := []models.User{}
	for rows.Next() {
		var user models.User
		if err := rows.Scan(
			&user.ID, &user.Nickname, &user.Email, &user.PasswordHash, &user.Role, &user.AvatarURL, &user.ProfileData, &user.AuthProvider, &user.AuthProviderID, &user.IsActive, &user.CreatedAt, &user.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("repository.ListAllUsers.Scan: %w", err)
		}
		users = append(users, user)
	}

	var total int
	err = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("repository.ListAllUsers.Count: %w", err)
	}

	return users, total, nil
}

func (r *Repository) UpdateRole(ctx context.Context, userID string, newRole string) error {
	query := `UPDATE users SET role = $1, updated_at = $2 WHERE id = $3`
	_, err := r.db.Exec(ctx, query, newRole, time.Now(), userID)
	if err != nil {
		return fmt.Errorf("repository.UpdateUserRole: %w", err)
	}
	return nil
}

// --- User Notes Methods ---
func (r *Repository) GetUserNoteByID(ctx context.Context, noteID int, userID string) (*models.UserNote, error) {
	note := &models.UserNote{}
	query := `SELECT id, user_id, title, content, entity_type, entity_id, is_published_to_forum, forum_post_id, created_at, updated_at
	          FROM user_notes WHERE id = $1 AND user_id = $2`
	err := r.db.QueryRow(ctx, query, noteID, userID).Scan(
		&note.ID, &note.UserID, &note.Title, &note.Content, &note.EntityType, &note.EntityID,
		&note.IsPublishedToForum, &note.ForumPostID, &note.CreatedAt, &note.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows || strings.Contains(err.Error(), "no rows") {
			return nil, models.ErrNotFound
		}
		return nil, fmt.Errorf("repository.GetUserNoteByID: %w", err)
	}
	return note, nil
}

func (r *Repository) GetLinksForNote(ctx context.Context, noteID int) ([]models.UserNoteLink, error) {
	links := []models.UserNoteLink{}
	query := `SELECT id, user_note_id, linked_entity_type, linked_entity_id_int, linked_entity_id_uuid, linked_entity_id_string, linked_description, created_at
	          FROM user_note_links WHERE user_note_id = $1`
	rows, err := r.db.Query(ctx, query, noteID)
	if err != nil {
		return nil, fmt.Errorf("repository.GetLinksForNote: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var link models.UserNoteLink
		if err := rows.Scan(&link.UserNoteID, &link.LinkedEntityType, &link.LinkedEntityIDInt, &link.LinkedEntityIDUUID, &link.LinkedEntityIDString, &link.LinkDescription, &link.CreatedAt); err != nil {
			return nil, fmt.Errorf("repository.GetLinksForNote.Scan: %w", err)
		}
		links = append(links, link)
	}
	return links, nil
}

func (r *Repository) ListUserNotes(ctx context.Context, userID string, page, limit int) ([]models.UserNote, int, error) {
	// Implement pagination similar to ListAllUsers
	notes := []models.UserNote{}
	offset := (page - 1) * limit
	query := `SELECT id, user_id, title, entity_type, entity_id, is_published_to_forum, created_at, updated_at
	          FROM user_notes WHERE user_id = $1 ORDER BY updated_at DESC LIMIT $2 OFFSET $3`
	rows, err := r.db.Query(ctx, query, userID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("repository.ListUserNotes: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var note models.UserNote
		// Scan fewer fields for list view if full content not needed
		if err := rows.Scan(&note.ID, &note.UserID, &note.Title, &note.EntityType, &note.EntityID, &note.IsPublishedToForum, &note.CreatedAt, &note.UpdatedAt); err != nil {
			return nil, 0, fmt.Errorf("repository.ListUserNotes.Scan: %w", err)
		}
		notes = append(notes, note)
	}

	var total int
	err = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM user_notes WHERE user_id = $1", userID).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("repository.ListUserNotes.Count: %w", err)
	}
	return notes, total, nil
}

func (r *Repository) CreateUserNote(ctx context.Context, userID string, data models.CreateUserNoteData) (*models.UserNote, error) {
	note := models.UserNote{
		UserID:     userID,
		Title:      data.Title,
		Content:    data.Content,
		EntityType: data.EntityType,
		EntityID:   data.EntityID,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	query := `INSERT INTO user_notes (user_id, title, content, entity_type, entity_id, created_at, updated_at)
	          VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`
	err := r.db.QueryRow(ctx, query, note.UserID, note.Title, note.Content, note.EntityType, note.EntityID, note.CreatedAt, note.UpdatedAt).Scan(&note.ID)
	if err != nil {
		return nil, fmt.Errorf("repository.CreateUserNote: %w", err)
	}
	return &note, nil
}

func (r *Repository) UpdateUserNote(ctx context.Context, noteID int, userID string, data models.UpdateUserNoteData) (*models.UserNote, error) {
	// Similar dynamic query building as r.Update for users
	// Ensure to check ownership: WHERE id = $X AND user_id = $Y
	// For brevity, a full dynamic implementation is omitted here.
	// Placeholder:
	currentNote, err := r.GetUserNoteByID(ctx, noteID, userID)
	if err != nil {
		return nil, err
	}
	if data.Title != nil {
		currentNote.Title = *data.Title
	}
	if data.Content != nil {
		currentNote.Content = *data.Content
	}
	currentNote.UpdatedAt = time.Now()

	query := `UPDATE user_notes SET title = $1, content = $2, updated_at = $3
              WHERE id = $4 AND user_id = $5
              RETURNING id, user_id, title, content, entity_type, entity_id, is_published_to_forum, forum_post_id, created_at, updated_at`
	err = r.db.QueryRow(ctx, query, currentNote.Title, currentNote.Content, currentNote.UpdatedAt, noteID, userID).Scan(
		&currentNote.ID, &currentNote.UserID, &currentNote.Title, &currentNote.Content, &currentNote.EntityType, &currentNote.EntityID,
		&currentNote.IsPublishedToForum, &currentNote.ForumPostID, &currentNote.CreatedAt, &currentNote.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("repository.UpdateUserNote: %w", err)
	}
	return currentNote, nil
}

func (r *Repository) DeleteUserNote(ctx context.Context, noteID int, userID string) error {
	query := `DELETE FROM user_notes WHERE id = $1 AND user_id = $2`
	cmdTag, err := r.db.Exec(ctx, query, noteID, userID)
	if err != nil {
		return fmt.Errorf("repository.DeleteUserNote: %w", err)
	}
	if cmdTag.RowsAffected() == 0 {
		return models.ErrNotFound // Or ErrForbidden if you prefer that for ownership failures
	}
	return nil
}

func (r *Repository) AddLinkToNote(ctx context.Context, noteID int, data models.AddLinkToNoteData) (*models.UserNoteLink, error) {
	link := models.UserNoteLink{
		UserNoteID:           noteID,
		LinkedEntityType:     data.LinkedEntityType,
		LinkedEntityIDInt:    data.LinkedEntityIDInt,
		LinkedEntityIDUUID:   data.LinkedEntityIDUUID,
		LinkedEntityIDString: data.LinkedEntityIDString,
		LinkDescription:      data.LinkDescription,
		CreatedAt:            time.Now(),
	}
	query := `INSERT INTO user_note_links (user_note_id, linked_entity_type, linked_entity_id_int, linked_entity_id_uuid, linked_entity_id_string, link_description, created_at)
	          VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`
	err := r.db.QueryRow(ctx, query, link.UserNoteID, link.LinkedEntityType, link.LinkedEntityIDInt, link.LinkedEntityIDUUID, link.LinkedEntityIDString, link.LinkDescription, link.CreatedAt).Scan(&link.ID)
	if err != nil {
		return nil, fmt.Errorf("repository.AddLinkToNote: %w", err)
	}
	return &link, nil
}

func (r *Repository) RemoveLinkFromNote(ctx context.Context, noteID, linkID int) error {
	query := `DELETE FROM user_note_links WHERE id = $1 AND user_note_id = $2`
	cmdTag, err := r.db.Exec(ctx, query, linkID, noteID)
	if err != nil {
		return fmt.Errorf("repository.RemoveLinkFromNote: %w", err)
	}
	if cmdTag.RowsAffected() == 0 {
		return models.ErrNotFound
	}
	return nil
}

func (r *Repository) MarkNoteAsPublished(ctx context.Context, noteID int, forumPostID int) error {
	query := `UPDATE user_notes SET is_published_to_forum = TRUE, forum_post_id = $1, updated_at = $2 WHERE id = $3`
	_, err := r.db.Exec(ctx, query, forumPostID, time.Now(), noteID)
	if err != nil {
		return fmt.Errorf("repository.MarkNoteAsPublished: %w", err)
	}
	return nil
}

// --- Other Profile Data Methods ---
func (r *Repository) GetNotifications(ctx context.Context, userID string, page, limit int) ([]models.Notification, int, error) {
	notifications := []models.Notification{}
	offset := (page - 1) * limit
	query := `SELECT id, recipient_user_id, actor_user_id, action_type, entity_type, entity_id, message, is_read, created_at
	          FROM notifications WHERE recipient_user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	rows, err := r.db.Query(ctx, query, userID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("repository.GetNotifications: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var notification models.Notification
		// Scan fewer fields for list view if full content not needed
		if err := rows.Scan(&notification.ID, &notification.RecipientUserID, &notification.ActorUserID, &notification.ActionType, &notification.EntityType, &notification.EntityID, &notification.Message, &notification.IsRead, &notification.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("repository.GetNotifications.Scan: %w", err)
		}
		notifications = append(notifications, notification)
	}

	var total int
	err = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM notifications WHERE recipient_user_id = $1", userID).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("repository.GetNotifications.Count: %w", err)
	}
	return notifications, total, nil
}

func (r *Repository) GetFavArtworks(ctx context.Context, userID string, page, limit int) ([]models.UserFavArtworkEntry, int, error) {
	offset := (page - 1) * limit

	// 1. Get artwork_ids and total count of favorites
	var artworkIDs []int64
	var favoritedAtTimes []time.Time

	queryFavs := `SELECT ufa.artwork_id, ufa.created_at
	          FROM user_favorite_artworks ufa WHERE ufa.user_id = $1 ORDER BY ufa.created_at DESC LIMIT $2 OFFSET $3`
	rows, err := r.db.Query(ctx, queryFavs, userID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("repository.GetFavArtworks.QueryFavs: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var artworkID int64
		var favTime time.Time

		if err := rows.Scan(&artworkID, &favTime); err != nil {
			return nil, 0, fmt.Errorf("repository.GetFavArtworks.ScanFavIDs: %w", err)
		}
		artworkIDs = append(artworkIDs, artworkID)
		favoritedAtTimes = append(favoritedAtTimes, favTime)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("repository.GetFavArtworks.RowsErr: %w", err)
	}

	var total int
	err = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM user_favorite_artworks WHERE user_id = $1", userID).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("repository.GetFavArtworks.Count: %w", err)
	}

	// 2. Fetch artwork details for the retrieved IDs
	artworksQuery := `
        SELECT
            a.id, a.title, a.thumbnail_url,
            ar.name as artist_name
        FROM artworks a
        LEFT JOIN artists ar ON a.artist_id = ar.id
        WHERE a.id = ANY($1::bigint[])` // Use ANY for array of IDs

	artworkRows, err := r.db.Query(ctx, artworksQuery, artworkIDs)
	if err != nil {
		return nil, total, fmt.Errorf("repository.GetFavArtworks.QueryArtworks: %w", err)
	}
	defer artworkRows.Close()

	favArtworksMap := make(map[int64]models.UserFavArtworkEntry)
	for artworkRows.Next() {
		var art models.UserFavArtworkEntry
		var artistName sql.NullString // Handle potentially NULL artist name
		if err := artworkRows.Scan(&art.Artwork.ID, &art.Artwork.Title, &art.Artwork.ThumbnailURL, &artistName); err != nil {
			return nil, total, fmt.Errorf("repository.GetFavArtworks.ScanArtworks: %w", err)
		}
		if artistName.Valid {
			art.Artwork.ArtistName = artistName.String
		}
		// You might want to add the 'favorited_at' time to the Artwork struct for display
		// For now, just populating the map.
		favArtworksMap[art.Artwork.ID] = art
	}
	if err := artworkRows.Err(); err != nil {
		return nil, 0, fmt.Errorf("repository.GetFavArtworks.ArtworkRowsErr: %w", err)
	}

	// Order results according to artworkIDs (which were ordered by favorite time)
	orderedFavArtworks := make([]models.UserFavArtworkEntry, 0, len(artworkIDs))
	for i, id := range artworkIDs {
		if art, ok := favArtworksMap[id]; ok {
			art.FavoritedAt = favoritedAtTimes[i]
			orderedFavArtworks = append(orderedFavArtworks, art)
		}
	}

	return orderedFavArtworks, total, nil
}

func (r *Repository) GetSavedForumPosts(ctx context.Context, userID string, page, limit int) ([]models.UserSavedPostEntry, int, error) {
	offset := (page - 1) * limit
	var postIDs []int64
	var savedTimes []time.Time

	querySaved := `SELECT post_id, created_at 
	           FROM user_saved_forum_posts WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	rows, err := r.db.Query(ctx, querySaved, userID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("repository.GetSavedForumPosts: %w", err)
	}
	defer rows.Close()

	var total int
	err = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM user_saved_forum_posts WHERE user_id = $1", userID).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("repository.GetSavedForumPosts.Count: %w", err)
	}
	if len(postIDs) == 0 {
		return []models.UserSavedPostEntry{}, total, nil
	}

	postsQuery := `
        SELECT fp.id, fp.title, fp.category_id, c.name as category_name,
               u.nickname as author_nickname, fp.last_activity_at
        FROM forum_posts fp
        JOIN users u ON fp.user_id = u.id
        LEFT JOIN forum_categories c ON fp.category_id = c.id
        WHERE fp.id = ANY($1::bigint[])`
	postRows, err := r.db.Query(ctx, postsQuery, postIDs)
	if err != nil {
		return nil, total, fmt.Errorf("repository.GetSavedForumPosts.QueryPosts: %w", err)
	}

	// Order results according to postIDs (which were ordered by saved time)
	postsMap := make(map[int64]models.UserSavedPostEntry)
	for postRows.Next() {
		var post models.UserSavedPostEntry
		if err := postRows.Scan(&post.Post.ID, &post.Post.Title, &post.Post.CategoryID, &post.Post.CategoryName, &post.Post.AuthorNickname, &post.Post.LastActivityAt); err != nil {
			return nil, total, fmt.Errorf("repository.GetFavArtworks.ScanArtworks: %w", err)
		}
		postsMap[post.Post.ID] = post
	}
	if err := postRows.Err(); err != nil {
		return nil, 0, fmt.Errorf("repository.GetSavedForumPosts.PostRowsErr: %w", err)
	}

	orderedPosts := make([]models.UserSavedPostEntry, 0, len(postIDs))
	for i, id := range postIDs {
		if post, ok := postsMap[id]; ok {
			post.SavedAt = savedTimes[i]
			orderedPosts = append(orderedPosts, post)
		}
	}

	return orderedPosts, total, nil
}
