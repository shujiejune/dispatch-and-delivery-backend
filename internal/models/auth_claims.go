package models

import "github.com/golang-jwt/jwt/v5"

type JwtCustomClaims struct {
	UserID string `json:"userID"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}
