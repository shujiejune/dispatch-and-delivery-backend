// Package logistics provides functionality for managing machine status and locations.
package logistics

import (
	"context"
	"fmt"
	"net/http"

	"dispatch-and-delivery/internal/models"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// RepositoryInterface declares database operations for machine records.
type RepositoryInterface interface {
	// FindMachineByID returns a machine by its UUID.
	FindMachineByID(ctx context.Context, id string) (*models.Machine, error)
	// UpdateMachine updates the machine status and location.
	UpdateMachine(ctx context.Context, m *models.Machine) error
	// ListMachines returns all machines in the fleet.
	ListMachines(ctx context.Context) ([]*models.Machine, error)
}

// Repository implements RepositoryInterface using PostgreSQL.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository creates a Repository instance.
func NewRepository(db *pgxpool.Pool) RepositoryInterface {
	return &Repository{db: db}
}

// FindMachineByID fetches a single machine. Returns models.ErrNotFound if none exist.
func (r *Repository) FindMachineByID(ctx context.Context, id string) (*models.Machine, error) {
	query := `
        SELECT id, type, status,
               COALESCE(ST_Y(current_location::geometry), 0) AS lat,
               COALESCE(ST_X(current_location::geometry), 0) AS lon,
               battery_level, created_at, updated_at
        FROM machines WHERE id = $1`
	row := r.db.QueryRow(ctx, query, id)
	m := &models.Machine{}
	err := row.Scan(&m.ID, &m.Type, &m.Status, &m.Latitude, &m.Longitude, &m.BatteryLevel, &m.CreatedAt, &m.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, models.ErrNotFound
		}
		return nil, fmt.Errorf("repository.FindMachineByID: %w", err)
	}
	return m, nil
}

// UpdateMachine updates status and location for a machine.
func (r *Repository) UpdateMachine(ctx context.Context, m *models.Machine) error {
	query := `
        UPDATE machines
        SET status = $2,
            current_location = ST_SetSRID(ST_MakePoint($3, $4), 4326),
            battery_level = $5,
            updated_at = now()
        WHERE id = $1`
	cmd, err := r.db.Exec(ctx, query, m.ID, m.Status, m.Longitude, m.Latitude, m.BatteryLevel)
	if err != nil {
		return fmt.Errorf("repository.UpdateMachine: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return models.ErrNotFound
	}
	return nil
}

// ListMachines retrieves all machines in the database.
func (r *Repository) ListMachines(ctx context.Context) ([]*models.Machine, error) {
	query := `
        SELECT id, type, status,
               COALESCE(ST_Y(current_location::geometry), 0) AS lat,
               COALESCE(ST_X(current_location::geometry), 0) AS lon,
               battery_level, created_at, updated_at
        FROM machines ORDER BY created_at`
	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("repository.ListMachines: %w", err)
	}
	defer rows.Close()

	var machines []*models.Machine
	for rows.Next() {
		m := &models.Machine{}
		if err := rows.Scan(&m.ID, &m.Type, &m.Status, &m.Latitude, &m.Longitude, &m.BatteryLevel, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, fmt.Errorf("repository.ListMachines scan: %w", err)
		}
		machines = append(machines, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("repository.ListMachines rows: %w", err)
	}
	return machines, nil
}

// ServiceInterface describes business logic for machine status management.
type ServiceInterface interface {
	// SetStatus updates a machine's status and location.
	SetStatus(ctx context.Context, machineID string, req models.MachineStatusUpdateRequest) error
	// ListMachines lists all registered machines.
	ListMachines(ctx context.Context) ([]*models.Machine, error)
}

// Service implements ServiceInterface.
type Service struct {
	repo RepositoryInterface
}

// NewService creates a service with the given repository.
func NewService(repo RepositoryInterface) ServiceInterface {
	return &Service{repo: repo}
}

// SetStatus validates and persists a machine status update.
func (s *Service) SetStatus(ctx context.Context, machineID string, req models.MachineStatusUpdateRequest) error {
	machine, err := s.repo.FindMachineByID(ctx, machineID)
	if err != nil {
		return err
	}

	machine.Status = req.Status
	machine.Latitude = req.Latitude
	machine.Longitude = req.Longitude
	// Battery level is left untouched here, but could also be updated from req.
	return s.repo.UpdateMachine(ctx, machine)
}

// ListMachines delegates to the repository to fetch all machines.
func (s *Service) ListMachines(ctx context.Context) ([]*models.Machine, error) {
	return s.repo.ListMachines(ctx)
}

// Handler exposes HTTP endpoints for machine management.
type Handler struct {
	svc ServiceInterface
}

// NewHandler constructs a Handler with the provided service.
func NewHandler(svc ServiceInterface) *Handler {
	return &Handler{svc: svc}
}

// GetFleet returns the entire fleet with their current status.
func (h *Handler) GetFleet(c echo.Context) error {
	machines, err := h.svc.ListMachines(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "failed to list machines"})
	}
	return c.JSON(http.StatusOK, machines)
}

// SetMachineStatus handles PUT /fleet/:machineId/status requests.
func (h *Handler) SetMachineStatus(c echo.Context) error {
	machineID := c.Param("machineId")
	var req models.MachineStatusUpdateRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "invalid request body"})
	}
	if err := h.svc.SetStatus(c.Request().Context(), machineID, req); err != nil {
		if err == models.ErrNotFound {
			return c.JSON(http.StatusNotFound, models.ErrorResponse{Message: "machine not found"})
		}
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "failed to update machine"})
	}
	return c.NoContent(http.StatusNoContent)
}

// RegisterAdminRoutes attaches machine status routes to the given Echo group.
func RegisterAdminRoutes(g *echo.Group, h *Handler) {
	g.GET("/fleet", h.GetFleet)
	g.PUT("/fleet/:machineId/status", h.SetMachineStatus)
}
