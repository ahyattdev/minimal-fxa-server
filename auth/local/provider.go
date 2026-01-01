// Package local implements local username/password authentication
package local

import (
	"context"
	"crypto/sha256"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/ahyattdev/minimal-fxa-server/auth"
	"github.com/ahyattdev/minimal-fxa-server/database"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Provider implements local username/password authentication
type Provider struct {
	db            *gorm.DB
	loginTemplate *template.Template
	onSuccess     func(w http.ResponseWriter, r *http.Request, user *auth.User)
}

// Config holds configuration for the local auth provider
type Config struct {
	DB        *gorm.DB
	OnSuccess func(w http.ResponseWriter, r *http.Request, user *auth.User)
}

// NewProvider creates a new local authentication provider
func NewProvider(cfg Config) *Provider {
	return &Provider{
		db:            cfg.DB,
		loginTemplate: template.Must(template.New("login").Parse(loginHTML)),
		onSuccess:     cfg.OnSuccess,
	}
}

// Type returns the provider type
func (p *Provider) Type() string {
	return "local"
}

// Authenticate validates username/password and returns the user
func (p *Provider) Authenticate(ctx context.Context, email, password string) (*auth.User, error) {
	var localUser database.LocalUser
	if err := p.db.WithContext(ctx).Where("email = ?", email).First(&localUser).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, auth.ErrInvalidCredentials{Message: "invalid email or password"}
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(localUser.PasswordHash), []byte(password)); err != nil {
		return nil, auth.ErrInvalidCredentials{Message: "invalid email or password"}
	}

	return &auth.User{
		ID:       localUser.ID,
		Email:    localUser.Email,
		Verified: true, // Local users are always verified
	}, nil
}

// HandleLogin renders the login page
func (p *Provider) HandleLogin(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{
		"Error": r.URL.Query().Get("error"),
	}
	w.Header().Set("Content-Type", "text/html")
	p.loginTemplate.Execute(w, data)
}

// HandleCallback processes the login form submission
func (p *Provider) HandleCallback(w http.ResponseWriter, r *http.Request) (*auth.User, error) {
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("failed to parse form: %w", err)
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	if email == "" || password == "" {
		return nil, auth.ErrInvalidCredentials{Message: "email and password required"}
	}

	user, err := p.Authenticate(r.Context(), email, password)
	if err != nil {
		return nil, err
	}

	slog.Info("Local user authenticated", "email", email, "userID", user.ID)
	return user, nil
}

// GetUserByID retrieves a user by their ID
func (p *Provider) GetUserByID(ctx context.Context, id string) (*auth.User, error) {
	var localUser database.LocalUser
	if err := p.db.WithContext(ctx).Where("id = ?", id).First(&localUser).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, auth.ErrUserNotFound{ID: id}
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	return &auth.User{
		ID:       localUser.ID,
		Email:    localUser.Email,
		Verified: true,
	}, nil
}

// CreateUser creates a new local user (used by CLI)
func (p *Provider) CreateUser(ctx context.Context, email, password string) (*auth.User, error) {
	// Generate user ID from email
	hash := sha256.Sum256([]byte(email))
	userID := fmt.Sprintf("%x", hash)[:32]

	// Hash the password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	localUser := database.LocalUser{
		ID:           userID,
		Email:        email,
		PasswordHash: string(passwordHash),
	}

	if err := p.db.WithContext(ctx).Create(&localUser).Error; err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	slog.Info("Created local user", "email", email, "userID", userID)

	return &auth.User{
		ID:       userID,
		Email:    email,
		Verified: true,
	}, nil
}

// DeleteUser deletes a local user (used by CLI)
func (p *Provider) DeleteUser(ctx context.Context, email string) error {
	result := p.db.WithContext(ctx).Where("email = ?", email).Delete(&database.LocalUser{})
	if result.Error != nil {
		return fmt.Errorf("failed to delete user: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return auth.ErrUserNotFound{ID: email}
	}

	slog.Info("Deleted local user", "email", email)
	return nil
}

// ChangePassword changes a user's password (used by CLI)
func (p *Provider) ChangePassword(ctx context.Context, email, newPassword string) error {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	result := p.db.WithContext(ctx).Model(&database.LocalUser{}).
		Where("email = ?", email).
		Update("password_hash", string(passwordHash))

	if result.Error != nil {
		return fmt.Errorf("failed to update password: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return auth.ErrUserNotFound{ID: email}
	}

	slog.Info("Changed password for local user", "email", email)
	return nil
}

// ListUsers returns all local users (used by CLI)
func (p *Provider) ListUsers(ctx context.Context) ([]auth.User, error) {
	var localUsers []database.LocalUser
	if err := p.db.WithContext(ctx).Find(&localUsers).Error; err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	users := make([]auth.User, len(localUsers))
	for i, lu := range localUsers {
		users[i] = auth.User{
			ID:       lu.ID,
			Email:    lu.Email,
			Verified: true,
		}
	}

	return users, nil
}

const loginHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in to Firefox</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 16px;
            padding: 48px 40px;
            width: 100%;
            max-width: 400px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
        }
        .logo {
            text-align: center;
            margin-bottom: 32px;
        }
        .logo svg {
            width: 64px;
            height: 64px;
        }
        h1 {
            text-align: center;
            color: #1a1a2e;
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 8px;
        }
        .subtitle {
            text-align: center;
            color: #666;
            font-size: 14px;
            margin-bottom: 32px;
        }
        .error {
            background: #fee2e2;
            border: 1px solid #fecaca;
            color: #dc2626;
            padding: 12px 16px;
            border-radius: 8px;
            margin-bottom: 24px;
            font-size: 14px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            color: #374151;
            font-size: 14px;
            font-weight: 500;
            margin-bottom: 6px;
        }
        input[type="email"],
        input[type="password"] {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid #e5e7eb;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        input:focus {
            outline: none;
            border-color: #0060df;
            box-shadow: 0 0 0 3px rgba(0, 96, 223, 0.1);
        }
        button {
            width: 100%;
            padding: 14px;
            background: #0060df;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
        }
        button:hover {
            background: #0250bb;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <svg viewBox="0 0 97.8 101" xmlns="http://www.w3.org/2000/svg">
                <defs>
                    <linearGradient id="firefox-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" style="stop-color:#ff9500"/>
                        <stop offset="100%" style="stop-color:#ff0039"/>
                    </linearGradient>
                </defs>
                <circle cx="48.9" cy="50.5" r="45" fill="url(#firefox-grad)"/>
            </svg>
        </div>
        <h1>Sign in</h1>
        <p class="subtitle">Enter your email and password</p>
        
        {{if .Error}}
        <div class="error">{{.Error}}</div>
        {{end}}
        
        <form method="POST" action="">
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required autofocus>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Sign in</button>
        </form>
    </div>
</body>
</html>`
