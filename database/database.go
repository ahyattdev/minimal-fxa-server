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
	ID           string `gorm:"primaryKey"`
	UserID       string `gorm:"index;not null"`
	DeviceID     *string
	CreatedAt    time.Time
	LastAccessAt time.Time
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
	err = db.AutoMigrate(&Device{}, &AuthCode{}, &OAuthToken{}, &Session{})
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
}
