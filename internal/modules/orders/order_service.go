package order

import (
	"context"
	"dispatch-and-delivery/internal/models"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MapsServiceInterface defines the contract for an external mapping service
// like Google Maps API, used to get route and time estimations.
// This would be implemented in a separate package, e.g., `pkg/maps`.
type MapsServiceInterface interface {
	GetDirections(ctx context.Context, origin, destination string) ([]*models.RouteOption, error)
}

// ServiceInterface defines the contract for the order service.
type ServiceInterface interface {
	// New methods for the two-step order process
	GetRouteOptions(ctx context.Context, req models.RouteRequest) ([]*models.RouteOption, error)
	CreateOrder(ctx context.Context, userID string, req models.CreateOrderRequest) (*models.Order, error)
	GetOrderDetails(ctx context.Context, orderID int, userID string, role string) (*models.Order, error)
	ListUserOrders(ctx context.Context, userID string, page, limit int) ([]*models.Order, int, error)
	ListAllOrders(ctx context.Context, page, limit int) ([]*models.Order, int, error)
	AdminUpdateOrder(ctx context.Context, orderID int, req models.AdminUpdateOrderRequest) (*models.Order, error)
	CancelOrder(ctx context.Context, orderID int, userID string) error
	ConfirmAndPay(ctx context.Context, userID string, orderID int, req models.PaymentRequest) (*models.Order, error)
	SubmitFeedback(ctx context.Context, userID string, orderID int, req models.FeedbackRequest) error
}

// PaymentServiceInterface defines the contract for a payment processing service.
type PaymentServiceInterface interface {
	ProcessPayment(ctx context.Context, userID string, amount float64, paymentMethodID string) (string, error)
}

// Service implements the order service logic.
type Service struct {
	repo           RepositoryInterface
	mapsService    MapsServiceInterface // For interacting with an external maps API.
	routeCache     map[string]*models.RouteOption // In-memory cache for route options
	routeCacheLock sync.RWMutex
	paymentService PaymentServiceInterface
}

// NewService creates a new order service.
func NewService(repo RepositoryInterface, mapsService MapsServiceInterface, paymentService PaymentServiceInterface) *Service {
	return &Service{
		repo:           repo,
		mapsService:    mapsService,
		routeCache:     make(map[string]*models.RouteOption),
		paymentService: paymentService,
	}
}

// GetRouteOptions fetches potential delivery routes and prices from a maps service.
func (s *Service) GetRouteOptions(ctx context.Context, req models.RouteRequest) ([]*models.RouteOption, error) {
	// 1. Call the external maps service to get directions.
	// This is a placeholder. In a real implementation, s.mapsSvc would call the Google Maps Directions API.
	routes, err := s.mapsService.GetDirections(ctx, req.PickupLocation, req.DeliveryLocation)
	if err != nil {
		return nil, fmt.Errorf("service.GetRouteOptions: failed to get directions: %w", err)
	}

	if len(routes) == 0 {
		return nil, errors.New("no routes found for the given locations")
	}

	// 2. Calculate pricing for each route.
	// Pricing logic can be complex, based on distance, time, drone availability, etc.
	// Here's a simplified example.
	for _, route := range routes {
		// Example pricing: base fee + price per minute
		price := 5.00 + (route.EstimatedDuration.Minutes() * 0.50)
		route.Price = price
	}

	// 3. In a real application, you would cache these options with their prices
	// for a short period (e.g., 5-10 minutes) under their generated IDs.
	// The client would then use one of these IDs to create the order.

	var options []*models.RouteOption
	s.routeCacheLock.Lock()
	defer s.routeCacheLock.Unlock()

	for _, route := range routes {
		optionID := uuid.New().String()
		option := &models.RouteOption{
			ID:                optionID,
			PickupLocation:    req.PickupLocation, // Carry over original locations
			DeliveryLocation:  req.DeliveryLocation,
			Price:             route.Price,
			EstimatedDuration: route.EstimatedDuration,
		}
		s.routeCache[optionID] = option
		options = append(options, option)
	}

	return options, nil
}

// CreateOrder creates a new order based on a user's selected route option.
func (s *Service) CreateOrder(ctx context.Context, userID string, req models.CreateOrderRequest) (*models.Order, error) {
	s.routeCacheLock.RLock()
	routeOption, ok := s.routeCache[req.RouteOptionID]
	s.routeCacheLock.RUnlock()

	if !ok {
		return nil, models.ErrRouteOptionExpired
	}

	// Create order using the details from the cached route option
	order, err := s.repo.Create(ctx, userID, req, routeOption.PickupLocation, routeOption.DeliveryLocation)
	if err != nil {
		return nil, fmt.Errorf("service.CreateOrder: %w", err)
	}

	// It's good practice to remove the route option from the cache after it has been used.
	s.routeCacheLock.Lock()
	delete(s.routeCache, req.RouteOptionID)
	s.routeCacheLock.Unlock()

	return order, nil
}

// GetOrderDetails retrieves a single order's details.
func (s *Service) GetOrderDetails(ctx context.Context, orderID int, userID string, role string) (*models.Order, error) {
	order, err := s.repo.FindByID(ctx, orderID)
	if err != nil {
		return nil, fmt.Errorf("service.GetOrderDetails: %w", err)
	}

	// Security check: ensure the user requesting the order is the one who owns it.
	if order.UserID != userID {
		return nil, models.ErrNotFound // Return NotFound to avoid leaking information
	}

	return order, nil
}

// ListUserOrders retrieves all orders for a specific user.
func (s *Service) ListUserOrders(ctx context.Context, userID string, page, limit int) ([]*models.Order, int, error) {
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20 // Default/max limit
	}
	orders, total, err := s.repo.ListByUserID(ctx, userID, page, limit)
	if err != nil {
		return nil, 0, fmt.Errorf("service.ListUserOrders: %w", err)
	}
	return orders, total, nil
}

// ListAllOrders lists all orders in the system.
func (s *Service) ListAllOrders(ctx context.Context, page, limit int) ([]*models.Order, int, error) {
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 50
	}
	return s.repo.ListAll(ctx, page, limit)
}

// CancelOrder cancels an order for a user.
func (s *Service) CancelOrder(ctx context.Context, orderID int, userID string) error {
	// First, retrieve the order to check its current status.
	order, err := s.GetOrderDetails(ctx, orderID, userID, "user") // This already checks ownership
	if err != nil {
		return err // Either not found or another DB error
	}

	// Business logic: an order can only be cancelled if it's in a 'pending' state.
	if order.Status != "pending" {
		return models.ErrOrderCannotBeCancelled // A new error type you'd define in models
	}

	return s.repo.UpdateStatusForUser(ctx, orderID, userID, "cancelled")
}

// --- Admin Service Methods ---

// AdminUpdateOrder updates an order's status or assigns a drone.
func (s *Service) AdminUpdateOrder(ctx context.Context, orderID int, req models.AdminUpdateOrderRequest) (*models.Order, error) {
	// You might add more validation here, e.g., checking if the drone_id is valid and available.
	order, err := s.repo.Update(ctx, orderID, req)
	if err != nil {
		return nil, fmt.Errorf("service.AdminUpdateOrder: %w", err)
	}
	return order, nil
}

// ConfirmAndPay confirms and pays for an order.
func (s *Service) ConfirmAndPay(ctx context.Context, userID string, orderID int, req models.PaymentRequest) (*models.Order, error) {
	// 1. Get the order details, ensuring it belongs to the user.
	order, err := s.GetOrderDetails(ctx, orderID, userID, "user")
	if err != nil {
		return nil, err // Handles not found or not authorized
	}

	// 2. Check if the order can be paid for.
	if order.Status != "pending" || order.PaymentStatus != "pending" {
		return nil, models.ErrOrderCannotBePaid
	}

	// 3. In a real app, the price would be stored with the order.
	// For this example, let's look up the price from the original route option.
	// This is a simplification and assumes the route details are still available or stored with the order.
	// We will use a mock price for this example.
	const mockPrice = 15.75 // This should be retrieved from the order itself.

	// 4. Process payment through the payment service.
	_, err = s.paymentService.ProcessPayment(ctx, userID, mockPrice, req.PaymentMethodID)
	if err != nil {
		// If payment fails, we could update the order status to 'payment_failed'
		s.repo.UpdatePaymentStatus(ctx, orderID, "payment_failed")
		return nil, fmt.Errorf("payment processing failed: %w", err)
	}

	// 5. Update payment status in our database.
	err = s.repo.UpdatePaymentStatus(ctx, orderID, "paid")
	if err != nil {
		// This is a critical error. The payment went through but we couldn't update our DB.
		// This requires robust error handling, like a retry mechanism or manual intervention alert.
		log.Printf("CRITICAL: Payment processed for order %d but failed to update status: %v", orderID, err)
		return nil, fmt.Errorf("failed to update order payment status after successful payment: %w", err)
	}

	// 6. Return the updated order details.
	order.PaymentStatus = "paid"
	order.UpdatedAt = time.Now() // Reflect the update time

	return order, nil
}

// SubmitFeedback allows a user to submit feedback for a completed order.
func (s *Service) SubmitFeedback(ctx context.Context, userID string, orderID int, req models.FeedbackRequest) error {
	// 1. Get the order details, ensuring it belongs to the user.
	order, err := s.GetOrderDetails(ctx, orderID, userID, "user")
	if err != nil {
		return err // Handles not found or not authorized
	}

	// 2. Check if feedback can be submitted for this order.
	// Typically, feedback is only allowed for 'delivered' orders.
	if order.Status != "delivered" {
		return models.ErrCannotSubmitFeedback
	}

	// 3. Check if feedback has already been submitted.
	if order.FeedbackRating.Valid {
		return models.ErrFeedbackAlreadySubmitted
	}

	// 4. Add the feedback via the repository.
	err = s.repo.AddFeedback(ctx, orderID, req.Rating, req.Comment)
	if err != nil {
		return fmt.Errorf("service.SubmitFeedback: %w", err)
	}

	return nil
}
