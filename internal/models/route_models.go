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