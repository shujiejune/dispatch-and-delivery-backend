package middleware

import (
	"dispatch-and-delivery/internal/models"
	"errors"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
)

// JWTMAuth configures and returns Echo's JWT middleware.
// It uses the jwtSecretKey from the config file (.env).
func JWTMAuth(jwtSecretKey string) echo.MiddlewareFunc {
	config := echojwt.Config{
		// NewClaimsFunc is required to specify the type of claims object to expect.
		// The middleware will use this to parse the claims from the token.
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(models.JwtCustomClaims)
		},
		// SigningKey is the secret key used to verify the JWT's signature.
		SigningKey: []byte(jwtSecretKey),
		// TokenLookup specifies where to look for the token.
		// Default is "header:Authorization:Bearer <token>". Can customize it if needed.
		// Example: "query:token,cookie:jwt"

		// SuccessHandler is called after a token is successfully validated.
		// I use it here to extract our custom claims and put them into the context
		SuccessHandler: func(c echo.Context) {
			// "user" is the default context key used by echo-jwt
			// c.Get("user") returns interface{}, so I need to type-assert it
			userToken := c.Get("user").(*jwt.Token)
			claims := userToken.Claims.(*models.JwtCustomClaims)

			c.Set("userID", claims.UserID)
			c.Set("userEmail", claims.Email)
			c.Logger().Infof("JWT Auth successful for user: %s", claims.UserID)
		},

		// ErrorHandler is called when there's an error in token validation (e.g., expired, invalid signature).
		ErrorHandler: func(c echo.Context, err error) error {
			// Log the detailed error on the server for debugging
			c.Logger().Errorf("JWT Error: %v", err)

			// Return a generic error message to the client
			if errors.Is(err, echojwt.ErrJWTMissing) {
				return c.JSON(http.StatusUnauthorized, models.ErrorResponse{Message: "Missing or malformed JWT"})
			}
			// Check for more specific errors from the golang-jwt library if wrapped
			// For example, if err is of type *jwt.ValidationError
			if errors.Is(err, jwt.ErrTokenMalformed) {
				return c.JSON(http.StatusUnauthorized, models.ErrorResponse{Message: "Token is malformed"})
			} else if errors.Is(err, jwt.ErrTokenExpired) {
				return c.JSON(http.StatusUnauthorized, models.ErrorResponse{Message: "Token has expired"})
			} else if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
				return c.JSON(http.StatusUnauthorized, models.ErrorResponse{Message: "Invalid token signature"})
			}

			return c.JSON(http.StatusUnauthorized, models.ErrorResponse{Message: "Invalid or expired JWT"})
		},
		// ContextKey: "user", this is default
	}
	return echojwt.WithConfig(config)
}

// AdminRequired checks if the authenticated user has the "ADMIN" role.
// Run after JWTMAuth, because it depends on the claims fetched from the context.
func AdminRequired() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// The JWTMAuth middleware's SuccessHandler should have placed it here.
			role, ok := c.Get("userRole").(string)
			if !ok {
				c.Logger().Error("Could not retrieve user role from context.")
				return c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "Could not process user role"})
			}

			if role != "ADMIN" {
				return c.JSON(http.StatusForbidden, models.ErrorResponse{Message: "Forbidden: Access is restricted to administrators"})
			}

			return next(c)
		}
	}
}
