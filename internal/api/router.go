package api

import (
	"net/http"

	"dispatch-and-delivery/internal/api/middleware"
	"dispatch-and-delivery/internal/modules/admin"
	"dispatch-and-delivery/internal/modules/logistics"
	"dispatch-and-delivery/internal/modules/orders"
	"dispatch-and-delivery/internal/modules/users"

	"github.com/labstack/echo/v4"
)

// SetupRoutes sets up all the API endpoints for the application.
func SetupRoutes(
	e *echo.Echo,
	userHandler *users.Handler,
	orderHandler *orders.Handler,
	logisticsHandler *logistics.Handler,
	adminHandler *admin.Handler,
	jwtSecret string,
) {
	// Initialize the JWT authentication middleware
	authMiddleware := middleware.JWTMAuth(jwtSecret)
	// Initialize an Admin role authorization middleware
	adminRequired := middleware.AdminRequired()

	// --- Public Routes ---
	e.GET("/", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"message": "Welcome to Dispatch and Delivery Platform!"})
	})

	authGroup := e.Group("/auth")
	{
		authGroup.POST("/signup", userHandler.Signup)
		authGroup.POST("/login", userHandler.Login)
		// Logout and ResetPassword
	}

	// --- User (Customer) Routes ---
	profileGroup := e.Group("/profile", authMiddleware)
	{

		// User Profile & Addresses
		profileGroup.GET("", userHandler.GetMyProfile)
		profileGroup.PUT("", userHandler.UpdateMyProfile)
		profileGroup.GET("/addresses", userHandler.ListMyAddresses)
		profileGroup.POST("/addresses", userHandler.AddAddress)
		profileGroup.PUT("/addresses/:addressId", userHandler.UpdateAddress)
		profileGroup.DELETE("/addresses/:addressId", userHandler.DeleteAddress)
	}

	// --- Order Routes ---
	orderGroup := e.Group("/orders", authMiddleware)
	{
		orderGroup.POST("/quote", orderHandler.GetDeliveryQuote) // Get route options and prices
		orderGroup.POST("", orderHandler.CreateOrder)
		orderGroup.GET("", orderHandler.ListMyOrders)
		orderGroup.GET("/:orderId", orderHandler.GetOrderDetails)
		orderGroup.PUT("/:orderId/cancel", orderHandler.CancelOrder)
		orderGroup.POST("/:orderId/pay", orderHandler.ConfirmAndPay)
		orderGroup.POST("/:orderId/feedback", orderHandler.SubmitFeedback)
	}

	// --- Logistics & Tracking Routes ---
	e.GET("/ws/orders/:orderId/track", logisticsHandler.HandleTracking, authMiddleware) // Potentially WebSocket

	// --- Admin Routes ---
	adminGroup := e.Group("/admin", authMiddleware, adminRequired)
	{
		// Order Management
		adminGroup.GET("/orders", adminHandler.GetAllOrders)                     // View all orders in the system
		adminGroup.GET("/orders/:orderId", adminHandler.GetAnyOrder)             // View details of any specific order
		adminGroup.POST("/orders/:orderId/reassign", adminHandler.ReassignOrder) // Manually reassign a failed delivery

		// Machine Management
		adminGroup.GET("/fleet", adminHandler.GetAllMachinesWithStatus)           // Get a list of all machines and their status
		adminGroup.PUT("/fleet/:machineId/status", adminHandler.SetMachineStatus) // e.g., Set to "under_maintenance"

		// User Management
		adminGroup.GET("/users", adminHandler.GetAllUsers) // View a list of all registered users
	}
}
