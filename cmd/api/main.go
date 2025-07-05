package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"dispatch-and-delivery/internal/api"
	"dispatch-and-delivery/internal/config"
	"dispatch-and-delivery/internal/modules/logistics"
	"dispatch-and-delivery/internal/modules/order"
	"dispatch-and-delivery/internal/modules/user"
	"dispatch-and-delivery/pkg/email"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func main() {
	// 1. --- Configuration ---
	// Load application configuration from environment variables or a config file.
	// This includes settings for the database, server port, JWT secrets, etc.
	cfg, err := config.LoadConfig(".")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	e := echo.New()
	e.Logger.Fatal(e.Start(":" + cfg.ServerPort))

	// 2. --- Middleware ---
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{ // Configure CORS appropriately
		AllowOrigins: []string{"http://localhost:5173", cfg.ClientOrigin}, // Your SvelteKit dev and prod origins
		AllowMethods: []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization},
	}))

	// 3. --- Database Connection ---
	// Initialize the PostgreSQL database connection pool.
	// This connection will be shared across all parts of the application that need it.
	dbConfig, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Unable to parse database configuration: %v", err)
	}

	dbPool, err := pgxpool.NewWithConfig(context.Background(), dbConfig)
	if err != nil {
		log.Fatalf("Unable to create connection pool: %v\n", err)
	}
	defer dbPool.Close()

	if err := dbPool.Ping(context.Background()); err != nil {
		log.Fatalf("Unable to ping database: %v\n", err)
	}
	e.Logger.Info("Successfully connected to the database!")

	// 3. --- Dependency Injection (Wiring everything up) ---
	// Initialize Google OAuth Config
	googleOAuthConfig := &oauth2.Config{
		RedirectURL:  cfg.GoogleOAuthRedirectURL,
		ClientID:     cfg.GoogleOAuthClientID,
		ClientSecret: cfg.GoogleOAuthClientSecret,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	sesSender, err := email.NewSESV2Sender(context.Background(), cfg.AWSRegion, cfg.EmailFromAddress)
	if err != nil {
		log.Fatalf("Failed to create SES sender: %v", err)
	}
	templateManager, err := email.NewTemplateManager()
	if err != nil {
		log.Fatalf("Failed to parse email templates: %v", err)
	}

	// --- Users Module ---
	userRepo := user.NewRepository(dbPool)
	userService := user.NewService(
		userRepo,
		sesSender,
		templateManager,
		cfg.JWTSecret,
		cfg.ClientOrigin,
		googleOAuthConfig,
	)
	userHandler := user.NewHandler(userService)

	// --- Orders Module ---
	orderRepo := order.NewRepository(dbPool)
	orderService := order.NewService(orderRepo, cfg.JWTSecret)
	orderHandler := order.NewHandler(orderService)

	// --- Logistics Module ---
	logisticsRepo := logistics.NewRepository(dbPool)
	logisticsService := logistics.NewService(logisticsRepo, orderService, cfg.JWTSecret)
	logisticsHandler := logistics.NewHandler(logisticsService)

	// 4. --- Initialize Router ---
	// Add more routes
	api.SetupRoutes(e, cfg.JWTSecret,
		userHandler,
		orderHandler,
		logisticsHandler,
	)

	// 5. --- Start Server with graceful shutdown logic ---
	go func() {
		if err := e.Start(":" + cfg.ServerPort); err != nil && err != http.ErrServerClosed {
			e.Logger.Fatal("shutting down the server an error occurred:", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := e.Shutdown(ctx); err != nil {
		e.Logger.Fatal("Server forced to shutdown:", err)
	}
	log.Println("Server exiting")
}
