package models

import "time"

type Address struct {
	ID            string    `json:"id" db:"id"`
	UserID        string    `json:"-" db:"user_id"`
	Label         string    `json:"label" db:"label"`
	StreetAddress string    `json:"street_address" db:"street_address"`
	IsDefault     bool      `json:"is_default" db:"is_default"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time `json:"updated_at" db:"updated_at"`
}

// AddAddressRequest defines the shape of the request body for creating a new address.
type AddAddressRequest struct {
	Label         string `json:"label" validate:"required,min=2"`
	StreetAddress string `json:"street_address" validate:"required,min=10"`
	IsDefault     bool   `json:"is_default"`
}

// UpdateAddressRequest defines the shape of the request body for updating an address.
type UpdateAddressRequest struct {
	Label         string `json:"label,omitempty"`
	StreetAddress string `json:"street_address,omitempty"`
	IsDefault     *bool  `json:"is_default,omitempty"` // Pointer to handle 'false' as a valid update
}
