// Package auth defines the authentication provider interface
package auth

import (
	"context"
	"net/http"
)

// User represents an authenticated user
type User struct {
	ID       string // Unique identifier (used as FxA uid)
	Email    string
	Verified bool
}

// Provider defines the interface for authentication backends
type Provider interface {
	// Type returns the provider type name (e.g., "local", "oidc")
	Type() string

	// Authenticate validates credentials and returns the user if valid.
	// For local auth: username/password validation
	// For OIDC: this may not be used directly (OIDC uses redirects)
	Authenticate(ctx context.Context, username, password string) (*User, error)

	// HandleLogin renders the login page or redirects to OIDC provider
	HandleLogin(w http.ResponseWriter, r *http.Request)

	// HandleCallback handles the authentication callback
	// For local auth: processes form submission
	// For OIDC: handles the OAuth callback with code exchange
	HandleCallback(w http.ResponseWriter, r *http.Request) (*User, error)

	// GetUserByID retrieves a user by their ID
	GetUserByID(ctx context.Context, id string) (*User, error)
}

// ErrInvalidCredentials is returned when authentication fails
type ErrInvalidCredentials struct {
	Message string
}

func (e ErrInvalidCredentials) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return "invalid credentials"
}

// ErrUserNotFound is returned when a user is not found
type ErrUserNotFound struct {
	ID string
}

func (e ErrUserNotFound) Error() string {
	return "user not found: " + e.ID
}
