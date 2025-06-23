package order

import (
	"net/http"
	"strconv"

	"dispatch-and-delivery/internal/models"
	"dispatch-and-delivery/pkg/utils"

	"github.com/labstack/echo/v4"
)

// Handler handles HTTP requests for orders.
type Handler struct {
	svc ServiceInterface
}

// NewHandler creates a new order handler.
func NewHandler(svc ServiceInterface) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) GetDeliveryQuote(c echo.Context) error {
	var req models.RouteRequest
	if err := c.Bind(&req); err != nil {
		return utils.RespondWithError(c, http.StatusBadRequest, "Invalid request body")
	}

	if err := utils.GetValidator().Validate(req); err != nil {
		return utils.RespondWithError(c, http.StatusBadRequest, err.Error())
	}

	options, err := h.svc.GetRouteOptions(c.Request().Context(), req)
	if err != nil {
		return utils.RespondWithError(c, http.StatusInternalServerError, "Failed to get delivery quotes")
	}

	return utils.RespondWithJSON(c, http.StatusOK, options)
}

func (h *Handler) CreateOrder(c echo.Context) error {
	userID, _, err := utils.ExtractUserInfo(c)
	if err != nil {
		return err
	}

	var req models.CreateOrderRequest
	if err := c.Bind(&req); err != nil {
		return utils.RespondWithError(c, http.StatusBadRequest, "Invalid request body")
	}
	if err := utils.GetValidator().Validate(req); err != nil {
		return utils.RespondWithError(c, http.StatusBadRequest, err.Error())
	}

	order, err := h.svc.CreateOrder(c.Request().Context(), userID, req)
	if err != nil {
		return utils.HandleServiceError(c, err)
	}

	return utils.RespondWithJSON(c, http.StatusCreated, order)
}

func (h *Handler) ListMyOrders(c echo.Context) error {
	userID, _, err := utils.ExtractUserInfo(c)
	if err != nil {
		return err
	}

	page, limit := utils.GetPageLimit(c)
	orders, total, err := h.svc.ListUserOrders(c.Request().Context(), userID, page, limit)
	if err != nil {
		return utils.RespondWithError(c, http.StatusInternalServerError, "Failed to retrieve orders")
	}

	return utils.RespondWithJSON(c, http.StatusOK, map[string]interface{}{"orders": orders, "total": total})
}

func (h *Handler) GetOrderDetails(c echo.Context) error {
	userID, role, err := utils.ExtractUserInfo(c)
	if err != nil {
		return err
	}

	orderID, err := strconv.Atoi(c.Param("orderId"))
	if err != nil {
		return utils.RespondWithError(c, http.StatusBadRequest, "Invalid order ID")
	}

	order, err := h.svc.GetOrderDetails(c.Request().Context(), orderID, userID, role)
	if err != nil {
		return utils.HandleServiceError(c, err)
	}

	return utils.RespondWithJSON(c, http.StatusOK, order)
}

func (h *Handler) CancelOrder(c echo.Context) error {
	userID, _, err := utils.ExtractUserInfo(c)
	if err != nil {
		return err
	}

	orderID, err := strconv.Atoi(c.Param("orderId"))
	if err != nil {
		return utils.RespondWithError(c, http.StatusBadRequest, "Invalid order ID")
	}

	if err := h.svc.CancelOrder(c.Request().Context(), orderID, userID); err != nil {
		return utils.HandleServiceError(c, err)
	}

	return c.NoContent(http.StatusNoContent)
}

func (h *Handler) ConfirmAndPay(c echo.Context) error {
	userID, _, err := utils.ExtractUserInfo(c)
	if err != nil {
		return err
	}

	orderID, err := strconv.Atoi(c.Param("orderId"))
	if err != nil {
		return utils.RespondWithError(c, http.StatusBadRequest, "Invalid order ID")
	}

	var req models.PaymentRequest
	if err := c.Bind(&req); err != nil {
		return utils.RespondWithError(c, http.StatusBadRequest, "Invalid request body")
	}
	if err := utils.GetValidator().Validate(req); err != nil {
		return utils.RespondWithError(c, http.StatusBadRequest, err.Error())
	}

	order, err := h.svc.ConfirmAndPay(c.Request().Context(), userID, orderID, req)
	if err != nil {
		return utils.HandleServiceError(c, err)
	}

	return utils.RespondWithJSON(c, http.StatusOK, order)
}

func (h *Handler) SubmitFeedback(c echo.Context) error {
	userID, _, err := utils.ExtractUserInfo(c)
	if err != nil {
		return err
	}

	orderID, err := strconv.Atoi(c.Param("orderId"))
	if err != nil {
		return utils.RespondWithError(c, http.StatusBadRequest, "Invalid order ID")
	}

	var req models.FeedbackRequest
	if err := c.Bind(&req); err != nil {
		return utils.RespondWithError(c, http.StatusBadRequest, "Invalid request body")
	}
	if err := utils.GetValidator().Validate(req); err != nil {
		return utils.RespondWithError(c, http.StatusBadRequest, err.Error())
	}

	if err := h.svc.SubmitFeedback(c.Request().Context(), userID, orderID, req); err != nil {
		return utils.HandleServiceError(c, err)
	}

	return c.NoContent(http.StatusAccepted)
}

func (h *Handler) ListAllOrders(c echo.Context) error {
	_, _, err := utils.ExtractUserInfo(c)
	if err != nil {
		return err // Assuming role check is done in middleware or service
	}

	page, limit := utils.GetPageLimit(c)
	orders, total, err := h.svc.ListAllOrders(c.Request().Context(), page, limit)
	if err != nil {
		return utils.RespondWithError(c, http.StatusInternalServerError, "Failed to list all orders")
	}
	return utils.RespondWithJSON(c, http.StatusOK, map[string]interface{}{"orders": orders, "total": total})
}

func (h *Handler) AdminUpdateOrder(c echo.Context) error {
	_, _, err := utils.ExtractUserInfo(c)
	if err != nil {
		return err
	}

	orderID, err := strconv.Atoi(c.Param("orderId"))
	if err != nil {
		return utils.RespondWithError(c, http.StatusBadRequest, "Invalid order ID")
	}

	var req models.AdminUpdateOrderRequest
	if err := c.Bind(&req); err != nil {
		return utils.RespondWithError(c, http.StatusBadRequest, "Invalid request body")
	}
	if err := utils.GetValidator().Validate(req); err != nil {
		return utils.RespondWithError(c, http.StatusBadRequest, err.Error())
	}

	order, err := h.svc.AdminUpdateOrder(c.Request().Context(), orderID, req)
	if err != nil {
		return utils.HandleServiceError(c, err)
	}

	return utils.RespondWithJSON(c, http.StatusOK, order)
}
