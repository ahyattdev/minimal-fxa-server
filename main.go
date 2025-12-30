package main

import (
	"crypto/ecdsa"
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

	// Parse JWT signing key (EC P-256 private key in PEM format)
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

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format
		key, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			slog.Error("Failed to parse JWT_PRIVATE_KEY", "error", err, "pkcs8_error", err2)
			os.Exit(1)
		}
		var ok bool
		privateKey, ok = key.(*ecdsa.PrivateKey)
		if !ok {
			slog.Error("JWT_PRIVATE_KEY is not an EC private key")
			os.Exit(1)
		}
	}
	slog.Info("JWT signing key loaded", "curve", privateKey.Curve.Params().Name)

	db, err := database.Connect(databaseURI)
	if err != nil {
		slog.Error("Failed to connect to database", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()

	autoconfigHandler := autoconfig.NewHandler(baseURL, syncServerURL)
	autoconfigHandler.RegisterRoutes(mux)

	oauthHandler := oauth.NewHandler(baseURL, "username", "password", db, privateKey)
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
