package models

import "time"

// TrackingEvent represents a single location update from a delivery machine.
type TrackingEvent struct {
	ID        string    `json:"id"`
	OrderID   string    `json:"order_id"`
	MachineID string    `json:"machine_id"`
	Latitude  float64   `json:"latitude"`
	Longitude float64   `json:"longitude"`
	CreatedAt time.Time `json:"created_at"`
}

// TrackingEventRequest contains the data required when a machine reports
// a new tracking event.
type TrackingEventRequest struct {
	MachineID string  `json:"machine_id"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}