package models

import (
	"database/sql"
	"time"
)

// Order represents a delivery order in the system.
type Order struct {
	ID               int             `json:"id"`
	UserID           string          `json:"user_id"`
	DroneID          sql.NullInt64   `json:"drone_id,omitempty"`
	Status           string          `json:"status"`
	PickupLocation   string          `json:"pickup_location"`
	DeliveryLocation string          `json:"delivery_location"`
	Items            []byte          `json:"items"` // Using JSONB
	PaymentStatus    string          `json:"payment_status"`
	FeedbackRating   sql.NullInt32   `json:"feedback_rating,omitempty"`
	FeedbackComment  sql.NullString  `json:"feedback_comment,omitempty"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
}

// CreateOrderRequest represents the data needed to create a new order from a chosen route option.
type CreateOrderRequest struct {
	RouteOptionID string `json:"route_option_id" validate:"required"`
	Items         []byte `json:"items" validate:"required"`
}

// AdminUpdateOrderRequest represents the data an admin can use to update an order.
type AdminUpdateOrderRequest struct {
	Status  *string `json:"status,omitempty" validate:"omitempty,oneof=pending processing in_transit delivered cancelled failed"`
	DroneID *int64  `json:"drone_id,omitempty" validate:"omitempty,gt=0"`
}

// PaymentRequest represents the data needed to pay for an order.
type PaymentRequest struct {
	PaymentMethodID string `json:"payment_method_id" validate:"required"`
}

// FeedbackRequest represents the data needed to submit feedback for an order.
type FeedbackRequest struct {
	Rating  int    `json:"rating" validate:"required,min=1,max=5"`
	Comment string `json:"comment,omitempty"`
} 