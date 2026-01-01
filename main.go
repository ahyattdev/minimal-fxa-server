package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"net/http"
	"os"

	"github.com/ahyattdev/minimal-fxa-server/autoconfig"
	"github.com/ahyattdev/minimal-fxa-server/database"
	"github.com/ahyattdev/minimal-fxa-server/oauth"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	port := os.Getenv("HTTP_PORT")
	if port == "" {
		port = "80"
	}

	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:" + port
	}

	syncServerURL := os.Getenv("SYNC_SERVER_URL")
	if syncServerURL == "" {
		syncServerURL = baseURL + "/token"
	}

	databaseURI := os.Getenv("DATABASE_URI")
	if databaseURI == "" {
		slog.Error("DATABASE_URI environment variable is required")
		os.Exit(1)
	}

	// Parse JWT signing key (RSA private key in PEM format)
	jwtKeyPEM := os.Getenv("JWT_PRIVATE_KEY")
	if jwtKeyPEM == "" {
		slog.Error("JWT_PRIVATE_KEY environment variable is required")
		os.Exit(1)
	}

	block, _ := pem.Decode([]byte(jwtKeyPEM))
	if block == nil {
		slog.Error("Failed to decode JWT_PRIVATE_KEY PEM block")
		os.Exit(1)
	}

	var privateKey *rsa.PrivateKey
	// Try PKCS1 format first (RSA PRIVATE KEY)
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		privateKey = key
	} else {
		// Try PKCS8 format (PRIVATE KEY)
		key, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			slog.Error("Failed to parse JWT_PRIVATE_KEY", "pkcs1_error", err, "pkcs8_error", err2)
			os.Exit(1)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			slog.Error("JWT_PRIVATE_KEY is not an RSA private key")
			os.Exit(1)
		}
	}
	slog.Info("JWT signing key loaded", "bits", privateKey.N.BitLen())

	// Parse VAPID keys for Web Push (optional - push notifications won't work without them)
	vapidPrivateKey := os.Getenv("VAPID_PRIVATE_KEY")
	vapidPublicKey := os.Getenv("VAPID_PUBLIC_KEY")
	vapidEmail := os.Getenv("VAPID_EMAIL")
	if vapidPrivateKey == "" || vapidPublicKey == "" {
		slog.Warn("VAPID_PRIVATE_KEY or VAPID_PUBLIC_KEY not set - push notifications disabled")
	} else {
		if vapidEmail == "" {
			vapidEmail = "mailto:admin@localhost"
		}
		slog.Info("VAPID keys loaded - push notifications enabled")
	}

	db, err := database.Connect(databaseURI)
	if err != nil {
		slog.Error("Failed to connect to database", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()

	autoconfigHandler := autoconfig.NewHandler(baseURL, syncServerURL)
	autoconfigHandler.RegisterRoutes(mux)

	vapidConfig := oauth.VAPIDConfig{
		PrivateKey: vapidPrivateKey,
		PublicKey:  vapidPublicKey,
		Subscriber: vapidEmail,
	}
	oauthHandler := oauth.NewHandler(baseURL, "username", "password", db, privateKey, vapidConfig)
	oauthHandler.RegisterRoutes(mux)

	mux.HandleFunc("/{path...}", func(w http.ResponseWriter, r *http.Request) {
		slog.Warn("Not found", "method", r.Method, "path", r.URL.Path)
		http.NotFound(w, r)
	})

	slog.Info("Starting server", "port", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		slog.Error("Server failed", "error", err)
		os.Exit(1)
	}
}
