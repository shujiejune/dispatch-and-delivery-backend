package utils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// GenerateSecureToken creates a random, URL-safe string.
func GenerateSecureToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("rand.Read failed: %w", err)
	}
	return hex.EncodeToString(b), nil
}
