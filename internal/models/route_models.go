package models

import "time"

// RouteRequest is the input from the user to get route options.
type RouteRequest struct {
	PickupLocation   string `json:"pickup_location" validate:"required"`
	DeliveryLocation string `json:"delivery_location" validate:"required"`
}

// RouteOption represents a single routing option with a price and estimated duration.
type RouteOption struct {
	ID                string        `json:"id"`
	PickupLocation    string        `json:"pickup_location"`
	DeliveryLocation  string        `json:"delivery_location"`
	Price             float64       `json:"price"`
	EstimatedDuration time.Duration `json:"estimated_duration"` // in nanoseconds
} 

// Route represents a persisted route calculated for an order.
// It stores the encoded polyline returned by Google Maps Directions API
// along with distance and duration metrics.  This data can later be used
// for tracking or re-displaying the route to users.
type Route struct {
	ID              string    `json:"id"`
	OrderID         string    `json:"order_id"`
	Polyline        string    `json:"polyline"`
	DistanceMeters  int       `json:"distance_meters"`
	DurationSeconds int       `json:"duration_seconds"`
	CreatedAt       time.Time `json:"created_at"`
}