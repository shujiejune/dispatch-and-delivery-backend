package logistics

import (
	"context"
	"fmt"

	"dispatch-and-delivery/internal/models"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// ------------------- Repository Layer -------------------

// AssignRepositoryInterface declares the database methods needed for
// assigning orders to available machines. Only the minimal set of
// operations are included for this example.
type AssignRepositoryInterface interface {
	// GetOrderDestination fetches the delivery location string for an order.
	GetOrderDestination(ctx context.Context, orderID string) (string, error)
	// ListIdleMachines returns all machines currently marked as IDLE.
	ListIdleMachines(ctx context.Context) ([]*models.Machine, error)
	// AssignOrder updates the order with the chosen machine and status.
	AssignOrder(ctx context.Context, orderID, machineID string) error
	// UpdateMachineStatus sets the machine's status value.
	UpdateMachineStatus(ctx context.Context, machineID, status string) error
}

// AssignRepository is a PostgreSQL implementation of AssignRepositoryInterface.
type AssignRepository struct {
	db *pgxpool.Pool
}

// NewAssignRepository creates a new repository instance.
func NewAssignRepository(db *pgxpool.Pool) AssignRepositoryInterface {
	return &AssignRepository{db: db}
}

// GetOrderDestination returns the delivery location of the specified order.
func (r *AssignRepository) GetOrderDestination(ctx context.Context, orderID string) (string, error) {
	query := `
        SELECT delivery_location
        FROM orders
        WHERE id = $1`
	var dest string
	err := r.db.QueryRow(ctx, query, orderID).Scan(&dest)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", models.ErrNotFound
		}
		return "", fmt.Errorf("repo.GetOrderDestination: %w", err)
	}
	return dest, nil
}

// ListIdleMachines retrieves all machines with status 'IDLE'.
func (r *AssignRepository) ListIdleMachines(ctx context.Context) ([]*models.Machine, error) {
	query := `
        SELECT id, type, status,
               COALESCE(ST_Y(current_location::geometry), 0) AS lat,
               COALESCE(ST_X(current_location::geometry), 0) AS lon,
               battery_level, created_at, updated_at
        FROM machines
        WHERE status = 'IDLE'`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("repo.ListIdleMachines: %w", err)
	}
	defer rows.Close()

	var machines []*models.Machine
	for rows.Next() {
		m := &models.Machine{}
		if err := rows.Scan(&m.ID, &m.Type, &m.Status, &m.Latitude, &m.Longitude, &m.BatteryLevel, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, fmt.Errorf("repo.ListIdleMachines scan: %w", err)
		}
		machines = append(machines, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("repo.ListIdleMachines rows: %w", err)
	}
	return machines, nil
}

// AssignOrder updates an order to use the given machine and sets status to IN_PROGRESS.
func (r *AssignRepository) AssignOrder(ctx context.Context, orderID, machineID string) error {
	query := `
        UPDATE orders
        SET machine_id = $2,
            status = 'IN_PROGRESS',
            updated_at = now()
        WHERE id = $1`
	cmd, err := r.db.Exec(ctx, query, orderID, machineID)
	if err != nil {
		return fmt.Errorf("repo.AssignOrder: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return models.ErrNotFound
	}
	return nil
}

// UpdateMachineStatus changes the status of a machine.
func (r *AssignRepository) UpdateMachineStatus(ctx context.Context, machineID, status string) error {
	query := `
        UPDATE machines
        SET status = $2,
            updated_at = now()
        WHERE id = $1`
	cmd, err := r.db.Exec(ctx, query, machineID, status)
	if err != nil {
		return fmt.Errorf("repo.UpdateMachineStatus: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return models.ErrNotFound
	}
	return nil
}

// ------------------- Service Layer -------------------

// AssignServiceInterface defines business logic for assigning orders.
type AssignServiceInterface interface {
	// AssignOrder chooses a machine for the order and updates both records.
	AssignOrder(ctx context.Context, orderID string) (*models.Machine, error)
}

// AssignService implements AssignServiceInterface.
type AssignService struct {
	repo AssignRepositoryInterface
}

// NewAssignService constructs a service with the provided repository.
func NewAssignService(repo AssignRepositoryInterface) *AssignService {
	return &AssignService{repo: repo}
}

// AssignOrder selects the best available machine for an order.
func (s *AssignService) AssignOrder(ctx context.Context, orderID string) (*models.Machine, error) {
	// Step 1: Retrieve the order destination.
	dest, err := s.repo.GetOrderDestination(ctx, orderID)
	if err != nil {
		return nil, err
	}

	// Step 2: Get all idle machines.
	machines, err := s.repo.ListIdleMachines(ctx)
	if err != nil {
		return nil, err
	}
	if len(machines) == 0 {
		return nil, fmt.Errorf("no idle machines available")
	}

	// Step 3: Choose the closest machine.
	// Pseudocode:
	//   bestMachine = machines[0]
	//   bestETA = computeETA(bestMachine.location, dest)
	//   for each m in machines[1:]:
	//       eta = computeETA(m.location, dest)
	//       if eta < bestETA:
	//           bestMachine = m
	//           bestETA = eta
	//   (computeETA would call a mapping service or use a distance formula.)
	bestMachine := machines[0]

	// Step 4: Update order and machine status in the database.
	if err := s.repo.AssignOrder(ctx, orderID, bestMachine.ID); err != nil {
		return nil, err
	}
	if err := s.repo.UpdateMachineStatus(ctx, bestMachine.ID, "IN_TRANSIT"); err != nil {
		return nil, err
	}

	return bestMachine, nil
}

// ------------------- HTTP Handler -------------------

// AssignHandler exposes an endpoint for (re)assigning orders to machines.
type AssignHandler struct {
	svc AssignServiceInterface
}

// NewAssignHandler creates a new handler with the given service.
func NewAssignHandler(svc AssignServiceInterface) *AssignHandler {
	return &AssignHandler{svc: svc}
}

// ReassignOrder handles POST /admin/orders/:orderId/reassign requests.
func (h *AssignHandler) ReassignOrder(c echo.Context) error {
	orderID := c.Param("orderId")

	machine, err := h.svc.AssignOrder(c.Request().Context(), orderID)
	if err != nil {
		if err == models.ErrNotFound {
			return c.JSON(http.StatusNotFound, models.ErrorResponse{Message: "order or machine not found"})
		}
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "failed to assign order"})
	}

	return c.JSON(http.StatusOK, machine)
}

// RegisterAdminRoutes attaches the reassign endpoint to an Echo group.
func RegisterAdminRoutesAssign(g *echo.Group, h *AssignHandler) {
	g.POST("/orders/:orderId/reassign", h.ReassignOrder)
}