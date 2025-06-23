package models

import "errors"

var (
	// ErrNotFound is returned when a requested resource is not found.
	ErrNotFound = errors.New("resource not found")

	// ErrOrderCannotBeCancelled is returned when an attempt is made to cancel an order
	// that is no longer in a cancellable state (e.g., 'in_transit' or 'delivered').
	ErrOrderCannotBeCancelled = errors.New("order cannot be cancelled")

	// ErrOrderCannotBePaid is returned when an attempt is made to pay for an order
	// that is not in a 'pending' state.
	ErrOrderCannotBePaid = errors.New("order is not in a state that can be paid for")

	// ErrRouteOptionExpired is returned when the user tries to create an order
	// with a route option ID that is expired or invalid.
	ErrRouteOptionExpired = errors.New("the delivery quote has expired, please request a new one")

	// ErrCannotSubmitFeedback is returned when a user tries to submit feedback for an order
	// that is not yet delivered.
	ErrCannotSubmitFeedback = errors.New("feedback can only be submitted for delivered orders")

	// ErrFeedbackAlreadySubmitted is returned when a user tries to submit feedback
	// for an order that already has feedback.
	ErrFeedbackAlreadySubmitted = errors.New("feedback has already been submitted for this order")
)

