package order

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

// RepositoryInterface defines the contract for the order repository.
type RepositoryInterface interface {
	Create(ctx context.Context, userID string, req models.CreateOrderRequest, pickupLocation, deliveryLocation string) (*models.Order, error)
	FindByID(ctx context.Context, orderID int) (*models.Order, error)
	ListByUserID(ctx context.Context, userID string, page, limit int) ([]*models.Order, int, error)
	ListAll(ctx context.Context, page, limit int) ([]*models.Order, int, error)
	Update(ctx context.Context, orderID int, req models.AdminUpdateOrderRequest) (*models.Order, error)
	UpdateStatusForUser(ctx context.Context, orderID int, userID string, status string) error
	UpdatePaymentStatus(ctx context.Context, orderID int, paymentStatus string) error
	AddFeedback(ctx context.Context, orderID int, rating int, comment string) error
}

// Repository implements the RepositoryInterface.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository creates a new order repository.
func NewRepository(db *pgxpool.Pool) RepositoryInterface {
	return &Repository{db: db}
}

// Create inserts a new order into the database.
func (r *Repository) Create(ctx context.Context, userID string, req models.CreateOrderRequest, pickupLocation, deliveryLocation string) (*models.Order, error) {
	query := `
		INSERT INTO orders (user_id, status, pickup_location, delivery_location, items, payment_status)
		VALUES ($1, 'pending', $2, $3, $4, 'pending')
		RETURNING id, user_id, drone_id, status, pickup_location, delivery_location, items, payment_status, feedback_rating, feedback_comment, created_at, updated_at`

	row := r.db.QueryRow(ctx, query, userID, pickupLocation, deliveryLocation, req.Items)
	order := &models.Order{}
	err := row.Scan(
		&order.ID,
		&order.UserID,
		&order.DroneID,
		&order.Status,
		&order.PickupLocation,
		&order.DeliveryLocation,
		&order.Items,
		&order.PaymentStatus,
		&order.FeedbackRating,
		&order.FeedbackComment,
		&order.CreatedAt,
		&order.UpdatedAt,
	)

	if err != nil {
		// A real implementation should check for foreign key constraints, etc.
		return nil, fmt.Errorf("repository.CreateOrder: %w", err)
	}

	return order, nil
}

// scanOrder is a helper function to scan a row into an Order model.
func (r *Repository) scanOrder(row pgx.Row) (*models.Order, error) {
	var order models.Order
	err := row.Scan(
		&order.ID,
		&order.UserID,
		&order.DroneID,
		&order.Status,
		&order.PickupLocation,
		&order.DeliveryLocation,
		&order.Items,
		&order.PaymentStatus,
		&order.FeedbackRating,
		&order.FeedbackComment,
		&order.CreatedAt,
		&order.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, models.ErrNotFound
		}
		return nil, fmt.Errorf("failed to scan order: %w", err)
	}
	return &order, nil
}

// FindByID retrieves a single order by its ID.
func (r *Repository) FindByID(ctx context.Context, orderID int) (*models.Order, error) {
	query := `
		SELECT id, user_id, drone_id, status, pickup_location, delivery_location, items, payment_status, feedback_rating, feedback_comment, created_at, updated_at
		FROM orders
		WHERE id = $1`
	
	row := r.db.QueryRow(ctx, query, orderID)
	order, err := r.scanOrder(row)
	if err != nil {
		return nil, fmt.Errorf("repository.FindByID: %w", err)
	}
	return order, nil
}

// ListByUserID retrieves all orders for a specific user with pagination.
func (r *Repository) ListByUserID(ctx context.Context, userID string, page, limit int) ([]*models.Order, int, error) {
	offset := (page - 1) * limit
	query := `
		SELECT id, user_id, drone_id, status, pickup_location, delivery_location, items, payment_status, feedback_rating, feedback_comment, created_at, updated_at
		FROM orders
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`

	rows, err := r.db.Query(ctx, query, userID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("repository.ListByUserID.Query: %w", err)
	}
	defer rows.Close()

	var orders []*models.Order
	for rows.Next() {
		order, err := r.scanOrder(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("repository.ListByUserID.Scan: %w", err)
		}
		orders = append(orders, order)
	}

	var total int
	err = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM orders WHERE user_id = $1", userID).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("repository.ListByUserID.Count: %w", err)
	}

	return orders, total, nil
}

// ListAll retrieves all orders in the system with pagination (for admin use).
func (r *Repository) ListAll(ctx context.Context, page, limit int) ([]*models.Order, int, error) {
	offset := (page - 1) * limit
	query := `
		SELECT id, user_id, drone_id, status, pickup_location, delivery_location, items, payment_status, feedback_rating, feedback_comment, created_at, updated_at
		FROM orders
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2`

	rows, err := r.db.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("repository.ListAll.Query: %w", err)
	}
	defer rows.Close()

	var orders []*models.Order
	for rows.Next() {
		order, err := r.scanOrder(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("repository.ListAll.Scan: %w", err)
		}
		orders = append(orders, order)
	}

	var total int
	err = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM orders").Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("repository.ListAll.Count: %w", err)
	}

	return orders, total, nil
}

// Update modifies an existing order's details (for admin use).
func (r *Repository) Update(ctx context.Context, orderID int, req models.AdminUpdateOrderRequest) (*models.Order, error) {
	var setClauses []string
	var args []interface{}
	argIdx := 1

	if req.Status != nil {
		setClauses = append(setClauses, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, *req.Status)
		argIdx++
	}
	if req.DroneID != nil {
		setClauses = append(setClauses, fmt.Sprintf("drone_id = $%d", argIdx))
		args = append(args, *req.DroneID)
		argIdx++
	}

	if len(setClauses) == 0 {
		// No fields to update, return the current order data
		return r.FindByID(ctx, orderID)
	}

	setClauses = append(setClauses, fmt.Sprintf("updated_at = $%d", argIdx))
	args = append(args, time.Now())
	argIdx++

	args = append(args, orderID) // For the WHERE clause

	query := fmt.Sprintf(`
		UPDATE orders SET %s
		WHERE id = $%d
		RETURNING id, user_id, drone_id, status, pickup_location, delivery_location, items, payment_status, feedback_rating, feedback_comment, created_at, updated_at`,
		strings.Join(setClauses, ", "), argIdx)

	row := r.db.QueryRow(ctx, query, args...)
	order, err := r.scanOrder(row)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, models.ErrNotFound
		}
		return nil, fmt.Errorf("repository.Update: %w", err)
	}

	return order, nil
}

// UpdateStatusForUser updates the status of an order for a specific user.
// This is used for actions like cancelling an order.
func (r *Repository) UpdateStatusForUser(ctx context.Context, orderID int, userID string, status string) error {
	query := `
		UPDATE orders
		SET status = $1, updated_at = NOW()
		WHERE id = $2 AND user_id = $3`

	cmdTag, err := r.db.Exec(ctx, query, status, orderID, userID)
	if err != nil {
		return fmt.Errorf("repository.UpdateStatusForUser: %w", err)
	}
	if cmdTag.RowsAffected() == 0 {
		return models.ErrNotFound // Order not found or not owned by the user
	}

	return nil
}

// UpdatePaymentStatus updates an order's payment status.
func (r *Repository) UpdatePaymentStatus(ctx context.Context, orderID int, paymentStatus string) error {
	query := `
		UPDATE orders
		SET payment_status = $1, updated_at = NOW()
		WHERE id = $2`

	cmdTag, err := r.db.Exec(ctx, query, paymentStatus, orderID)
	if err != nil {
		return fmt.Errorf("repository.UpdatePaymentStatus: %w", err)
	}
	if cmdTag.RowsAffected() == 0 {
		return models.ErrNotFound
	}
	return nil
}

// AddFeedback adds a rating and comment to an order.
func (r *Repository) AddFeedback(ctx context.Context, orderID int, rating int, comment string) error {
	query := `
		UPDATE orders
		SET feedback_rating = $1, feedback_comment = $2, updated_at = NOW()
		WHERE id = $3`

	cmdTag, err := r.db.Exec(ctx, query, rating, comment, orderID)
	if err != nil {
		return fmt.Errorf("repository.AddFeedback: %w", err)
	}
	if cmdTag.RowsAffected() == 0 {
		return models.ErrNotFound
	}
	return nil
}
