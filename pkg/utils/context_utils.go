package utils

import (
	"errors"
	"strconv"

	"github.com/labstack/echo/v4"
)

// GetUserIDFromContext retrieves userID from Echo context (set by JWT middleware)
func GetUserIDFromContext(c echo.Context) (string, error) {
	userIDVal := c.Get("userID")
	if userIDVal == nil {
		return "", errors.New("userID not found in context, user may not be authenticated")
	}
	userID, ok := userIDVal.(string)
	if !ok {
		return "", errors.New("userID in context is not of type string")
	}
	if userID == "" {
		return "", errors.New("userID in context is empty")
	}
	return userID, nil
}

// GetPageLimit extracts page and limit query params for pagination
func GetPageLimit(c echo.Context) (page int, limit int) {
	pageStr := c.QueryParam("page")
	limitStr := c.QueryParam("limit")

	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	limit, err = strconv.Atoi(limitStr)
	if err != nil || limit < 1 {
		limit = 20 // Default limit
	}
	if limit > 100 { // Max limit
		limit = 100
	}
	return page, limit
}
