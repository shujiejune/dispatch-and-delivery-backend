package logistics

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"dispatch-and-delivery/internal/models"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// GoogleMapAPIKey is a placeholder for the actual API key used to call
// Google Maps Directions API. Replace this with your real key in a
// production environment.
const GoogleMapAPIKey = "GOOGLE_MAPS_KEY"

// RouteRepositoryInterface declares the database operations needed for
// storing routes and retrieving order addresses.
// It is intentionally minimal for demonstration purposes.
type RouteRepositoryInterface interface {
	// GetOrderAddresses fetches the pickup and dropoff addresses for the given order.
	GetOrderAddresses(ctx context.Context, orderID string) (pickup, dropoff string, err error)
	// SaveRoute persists the computed route in the database.
	SaveRoute(ctx context.Context, r *models.Route) error
}

// RouteRepository is a PostgreSQL implementation of RouteRepositoryInterface.
type RouteRepository struct {
	db *pgxpool.Pool
}

// NewRouteRepository creates a new repository instance.
func NewRouteRepository(db *pgxpool.Pool) RouteRepositoryInterface {
	return &RouteRepository{db: db}
}

// GetOrderAddresses retrieves the pickup and dropoff address strings
// from the orders table. In a real application this might join the
// addresses table or another source.
func (r *RouteRepository) GetOrderAddresses(ctx context.Context, orderID string) (string, string, error) {
	query := `
        SELECT pickup_location, delivery_location
        FROM orders
        WHERE id = $1`
	var pickup, dropoff string
	err := r.db.QueryRow(ctx, query, orderID).Scan(&pickup, &dropoff)
	if err != nil {
		return "", "", fmt.Errorf("repo.GetOrderAddresses: %w", err)
	}
	return pickup, dropoff, nil
}

// SaveRoute inserts a new route record into the routes table.
func (r *RouteRepository) SaveRoute(ctx context.Context, route *models.Route) error {
	query := `
        INSERT INTO routes (order_id, polyline, distance_meters, duration_seconds)
        VALUES ($1, $2, $3, $4)
        RETURNING id, created_at`
	return r.db.QueryRow(ctx, query, route.OrderID, route.Polyline, route.DistanceMeters, route.DurationSeconds).
		Scan(&route.ID, &route.CreatedAt)
}

// ------------------- Service Layer -------------------

// RouteServiceInterface defines business logic around computing routes.
type RouteServiceInterface interface {
	ComputeRoute(ctx context.Context, orderID string) (*models.Route, error)
}

// RouteService implements RouteServiceInterface.
type RouteService struct {
	repo       RouteRepositoryInterface
	httpClient *http.Client
}

// NewRouteService creates a new service instance.
func NewRouteService(repo RouteRepositoryInterface) *RouteService {
	return &RouteService{
		repo:       repo,
		httpClient: &http.Client{},
	}
}

// googleDirectionsResponse is a minimal structure of the parts of the
// Google Maps Directions API response that we care about.
type googleDirectionsResponse struct {
	Routes []struct {
		OverviewPolyline struct {
			Points string `json:"points"`
		} `json:"overview_polyline"`
		Legs []struct {
			Distance struct {
				Value int `json:"value"`
			} `json:"distance"`
			Duration struct {
				Value int `json:"value"`
			} `json:"duration"`
		} `json:"legs"`
	} `json:"routes"`
}

// ComputeRoute calculates a route for the given order by calling the
// Google Maps Directions API.  The API key field is represented by the
// placeholder variable GoogleMapAPIKey.
func (s *RouteService) ComputeRoute(ctx context.Context, orderID string) (*models.Route, error) {
	// Step 1: Look up the order's pickup and dropoff addresses.
	pickup, dropoff, err := s.repo.GetOrderAddresses(ctx, orderID)
	if err != nil {
		return nil, err
	}

	// Step 2: Build the Directions API request.
	// Pseudocode of the algorithm:
	// 1. Construct the URL with origin, destination and the GoogleMapAPIKey.
	// 2. Send HTTP GET request to Google Maps Directions API.
	// 3. Parse the JSON response to extract the polyline, distance and duration.

	url := fmt.Sprintf("https://maps.googleapis.com/maps/api/directions/json?origin=%s&destination=%s&key=%s",
		pickup, dropoff, GoogleMapAPIKey)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("service.ComputeRoute build request: %w", err)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("service.ComputeRoute call directions: %w", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("service.ComputeRoute read body: %w", err)
	}

	var directions googleDirectionsResponse
	if err := json.Unmarshal(body, &directions); err != nil {
		return nil, fmt.Errorf("service.ComputeRoute unmarshal: %w", err)
	}

	if len(directions.Routes) == 0 || len(directions.Routes[0].Legs) == 0 {
		return nil, fmt.Errorf("service.ComputeRoute: no route returned")
	}

	leg := directions.Routes[0].Legs[0]
	route := &models.Route{
		OrderID:         orderID,
		Polyline:        directions.Routes[0].OverviewPolyline.Points,
		DistanceMeters:  leg.Distance.Value,
		DurationSeconds: leg.Duration.Value,
	}

	// Step 3: Save the computed route in the database.
	if err := s.repo.SaveRoute(ctx, route); err != nil {
		return nil, err
	}

	return route, nil
}

// ------------------- HTTP Handler -------------------

// RouteHandler exposes HTTP endpoints for computing routes.
type RouteHandler struct {
	svc RouteServiceInterface
}

// NewRouteHandler constructs a new RouteHandler.
func NewRouteHandler(svc RouteServiceInterface) *RouteHandler {
	return &RouteHandler{svc: svc}
}

// ComputeRoute handles POST /orders/:orderId/route.
func (h *RouteHandler) ComputeRoute(c echo.Context) error {
	orderID := c.Param("orderId")

	route, err := h.svc.ComputeRoute(c.Request().Context(), orderID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "failed to compute route"})
	}

	return c.JSON(http.StatusOK, route)
}

// RegisterRoutes attaches routing endpoints to the provided Echo group.
func RegisterRoutes(g *echo.Group, h *RouteHandler) {
	g.POST("/orders/:orderId/route", h.ComputeRoute)
}