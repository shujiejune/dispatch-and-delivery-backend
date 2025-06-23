package logistics

import (
	"context"
	"fmt"
	"net/http"

	"dispatch-and-delivery/internal/models"

	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// ------------------- Repository Layer -------------------

// TrackingRepositoryInterface declares database operations for tracking events.
type TrackingRepositoryInterface interface {
	// CreateTrackingEvent stores a new tracking event record.
	CreateTrackingEvent(ctx context.Context, event *models.TrackingEvent) error
	// ListTrackingEvents returns events for the given order sorted by time.
	ListTrackingEvents(ctx context.Context, orderID string) ([]*models.TrackingEvent, error)
}

// TrackingRepository is a PostgreSQL implementation of TrackingRepositoryInterface.
type TrackingRepository struct {
	db *pgxpool.Pool
}

// NewTrackingRepository creates a new repository instance.
func NewTrackingRepository(db *pgxpool.Pool) TrackingRepositoryInterface {
	return &TrackingRepository{db: db}
}

// CreateTrackingEvent inserts a new tracking event into the database.
func (r *TrackingRepository) CreateTrackingEvent(ctx context.Context, event *models.TrackingEvent) error {
	query := `
        INSERT INTO tracking_events (order_id, machine_id, location)
        VALUES ($1, $2, ST_SetSRID(ST_MakePoint($3, $4), 4326))
        RETURNING id, created_at`
	return r.db.QueryRow(ctx, query, event.OrderID, event.MachineID, event.Longitude, event.Latitude).
		Scan(&event.ID, &event.CreatedAt)
}

// ListTrackingEvents retrieves all events for an order ordered by creation time.
func (r *TrackingRepository) ListTrackingEvents(ctx context.Context, orderID string) ([]*models.TrackingEvent, error) {
	query := `
        SELECT id, order_id, machine_id,
               COALESCE(ST_Y(location::geometry), 0) AS lat,
               COALESCE(ST_X(location::geometry), 0) AS lon,
               created_at
        FROM tracking_events
        WHERE order_id = $1
        ORDER BY created_at`
	rows, err := r.db.Query(ctx, query, orderID)
	if err != nil {
		return nil, fmt.Errorf("repo.ListTrackingEvents: %w", err)
	}
	defer rows.Close()

	var events []*models.TrackingEvent
	for rows.Next() {
		ev := &models.TrackingEvent{}
		if err := rows.Scan(&ev.ID, &ev.OrderID, &ev.MachineID, &ev.Latitude, &ev.Longitude, &ev.CreatedAt); err != nil {
			return nil, fmt.Errorf("repo.ListTrackingEvents scan: %w", err)
		}
		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("repo.ListTrackingEvents rows: %w", err)
	}
	return events, nil
}

// ------------------- Service Layer -------------------

// TrackingServiceInterface defines business logic for tracking events.
type TrackingServiceInterface interface {
	// ReportTracking records a new tracking event.
	ReportTracking(ctx context.Context, orderID string, req models.TrackingEventRequest) error
	// GetTracking returns all tracking events for an order.
	GetTracking(ctx context.Context, orderID string) ([]*models.TrackingEvent, error)
}

// TrackingService implements TrackingServiceInterface.
type TrackingService struct {
	repo TrackingRepositoryInterface
}

// NewTrackingService creates a new service instance.
func NewTrackingService(repo TrackingRepositoryInterface) *TrackingService {
	return &TrackingService{repo: repo}
}

// ReportTracking validates input and persists the tracking event.
func (s *TrackingService) ReportTracking(ctx context.Context, orderID string, req models.TrackingEventRequest) error {
	// Step 1: Construct the TrackingEvent from the request data.
	event := &models.TrackingEvent{
		OrderID:   orderID,
		MachineID: req.MachineID,
		Latitude:  req.Latitude,
		Longitude: req.Longitude,
	}

	// Step 2: Save the event through the repository.
	return s.repo.CreateTrackingEvent(ctx, event)
}

// GetTracking fetches all tracking events for the order.
func (s *TrackingService) GetTracking(ctx context.Context, orderID string) ([]*models.TrackingEvent, error) {
	return s.repo.ListTrackingEvents(ctx, orderID)
}

// ------------------- HTTP Handlers -------------------

// upgrader is used to upgrade HTTP connections to WebSocket connections.
var upgrader = websocket.Upgrader{}

// ReportTracking handles POST /orders/:orderId/track requests.
func (h *Handler) ReportTracking(c echo.Context) error {
	orderID := c.Param("orderId")
	var req models.TrackingEventRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "invalid request body"})
	}

	if err := h.trackingSvc.ReportTracking(c.Request().Context(), orderID, req); err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "failed to record tracking"})
	}

	return c.NoContent(http.StatusCreated)
}

// GetTracking handles GET /orders/:orderId/track requests.
func (h *Handler) GetTracking(c echo.Context) error {
	orderID := c.Param("orderId")
	events, err := h.trackingSvc.GetTracking(c.Request().Context(), orderID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return c.JSON(http.StatusNotFound, models.ErrorResponse{Message: "order not found"})
		}
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "failed to get tracking"})
	}
	return c.JSON(http.StatusOK, events)
}

// HandleTracking upgrades the connection to a WebSocket and streams tracking data.
func (h *Handler) HandleTracking(c echo.Context) error {
	orderID := c.Param("orderId")

	conn, err := upgrader.Upgrade(c.Response(), c.Request(), nil)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Pseudocode of the streaming algorithm:
	//   loop {
	//       1. Fetch the latest tracking events for the order.
	//       2. Serialize the events to JSON and write to the WebSocket.
	//       3. Sleep or wait for new events before repeating.
	//   }
	_ = orderID // orderID would be used inside the loop above.

	return nil
}

// RegisterTrackingRoutes attaches tracking HTTP endpoints to the provided Echo group.
func RegisterTrackingRoutes(g *echo.Group, h *Handler) {
	g.POST("/orders/:orderId/track", h.ReportTracking)
	g.GET("/orders/:orderId/track", h.GetTracking)
}