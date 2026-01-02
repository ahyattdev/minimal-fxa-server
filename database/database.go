package database

import (
	"log/slog"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Device represents a registered Firefox device
type Device struct {
	ID            string `gorm:"primaryKey"`
	UserID        string `gorm:"index;not null"`
	Name          string
	Type          string
	PushCallback  *string
	PushPublicKey *string
	PushAuthKey   *string
	CreatedAt     time.Time
	LastAccessAt  time.Time
}

// AuthCode represents an OAuth authorization code
type AuthCode struct {
	Code                string `gorm:"primaryKey"`
	ClientID            string
	CodeChallenge       string
	CodeChallengeMethod string
	State               string
	KeysJWK             string
	UserID              string `gorm:"index"`
	Email               string // User's email address
	CreatedAt           time.Time
	ExpiresAt           time.Time
}

// OAuthToken represents an issued OAuth token
type OAuthToken struct {
	ID           uint   `gorm:"primaryKey"`
	AccessToken  string `gorm:"uniqueIndex"`
	RefreshToken string `gorm:"uniqueIndex"`
	UserID       string `gorm:"index;not null"`
	ClientID     string
	Scope        string
	DeviceID     *string
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

// Session represents a user session
type Session struct {
	ID           string `gorm:"primaryKey"`  // The raw sessionToken (hex)
	TokenID      string `gorm:"uniqueIndex"` // Derived Hawk tokenId (hex) - used for Hawk auth lookup
	HawkKey      []byte `gorm:"not null"`    // Derived reqHMACkey for Hawk MAC verification
	UserID       string `gorm:"index;not null"`
	DeviceID     *string
	CreatedAt    time.Time
	LastAccessAt time.Time
}

// User represents a Firefox Account user
type User struct {
	ID            string `gorm:"primaryKey"` // MD5 hash of username/email
	Email         string `gorm:"index"`      // User's email address
	KeysChangedAt int64  // Unix timestamp, set once on first login, used in JWT fxa-generation
	CreatedAt     time.Time
}

// LocalUser represents a locally authenticated user with password
type LocalUser struct {
	ID           string `gorm:"primaryKey"` // Same as User.ID
	Email        string `gorm:"uniqueIndex;not null"`
	PasswordHash string `gorm:"not null"` // bcrypt hash
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// OIDCState stores OIDC state tokens for CSRF protection
type OIDCState struct {
	State     string `gorm:"primaryKey"`
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Connect initializes the database connection and runs migrations
func Connect(databaseURI string) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(databaseURI), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		return nil, err
	}

	slog.Info("Connected to database")

	// Auto-migrate schemas
	err = db.AutoMigrate(&Device{}, &AuthCode{}, &OAuthToken{}, &Session{}, &User{}, &LocalUser{}, &OIDCState{})
	if err != nil {
		return nil, err
	}

	slog.Info("Database migrations completed")

	// Start cleanup routine
	go startCleanupRoutine(db)

	return db, nil
}

// startCleanupRoutine periodically removes expired auth codes and tokens
func startCleanupRoutine(db *gorm.DB) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	// Run once at startup
	cleanup(db)

	for range ticker.C {
		cleanup(db)
	}
}

func cleanup(db *gorm.DB) {
	now := time.Now()

	// Delete expired auth codes
	result := db.Where("expires_at < ?", now).Delete(&AuthCode{})
	if result.RowsAffected > 0 {
		slog.Info("Cleaned up expired auth codes", "count", result.RowsAffected)
	}

	// Delete expired OAuth tokens (expired more than 7 days ago to allow for refresh)
	expiredThreshold := now.Add(-7 * 24 * time.Hour)
	result = db.Where("expires_at < ?", expiredThreshold).Delete(&OAuthToken{})
	if result.RowsAffected > 0 {
		slog.Info("Cleaned up expired OAuth tokens", "count", result.RowsAffected)
	}

	// Delete stale sessions (not accessed in 30 days)
	staleThreshold := now.Add(-30 * 24 * time.Hour)
	result = db.Where("last_access_at < ?", staleThreshold).Delete(&Session{})
	if result.RowsAffected > 0 {
		slog.Info("Cleaned up stale sessions", "count", result.RowsAffected)
	}

	// Delete expired OIDC states
	result = db.Where("expires_at < ?", now).Delete(&OIDCState{})
	if result.RowsAffected > 0 {
		slog.Info("Cleaned up expired OIDC states", "count", result.RowsAffected)
	}
}
