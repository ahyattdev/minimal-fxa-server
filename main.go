package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/ahyattdev/minimal-fxa-server/auth"
	"github.com/ahyattdev/minimal-fxa-server/auth/local"
	"github.com/ahyattdev/minimal-fxa-server/auth/oidc"
	"github.com/ahyattdev/minimal-fxa-server/autoconfig"
	"github.com/ahyattdev/minimal-fxa-server/database"
	"github.com/ahyattdev/minimal-fxa-server/oauth"
	"github.com/ahyattdev/minimal-fxa-server/usermgmt"
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

	// Create auth provider based on AUTH_METHOD env var
	authMethod := strings.ToLower(os.Getenv("AUTH_METHOD"))
	if authMethod == "" {
		authMethod = "local"
	}

	var authProvider auth.Provider
	var localProvider *local.Provider // Keep reference for gRPC server
	switch authMethod {
	case "local":
		slog.Info("Using local authentication")
		localProvider = local.NewProvider(local.Config{
			DB: db,
		})
		authProvider = localProvider

		// Start gRPC server for user management
		socketPath := os.Getenv("FXA_SOCKET")
		if socketPath == "" {
			socketPath = usermgmt.DefaultSocketPath
		}
		go func() {
			if err := usermgmt.StartServer(localProvider, socketPath); err != nil {
				slog.Error("User management gRPC server failed", "error", err)
			}
		}()

	case "oidc":
		slog.Info("Using OIDC authentication")
		oidcIssuer := os.Getenv("OIDC_ISSUER")
		oidcClientID := os.Getenv("OIDC_CLIENT_ID")
		oidcClientSecret := os.Getenv("OIDC_CLIENT_SECRET")
		oidcRedirectURL := os.Getenv("OIDC_REDIRECT_URL")
		if oidcRedirectURL == "" {
			oidcRedirectURL = baseURL + "/oidc/callback"
		}

		if oidcIssuer == "" || oidcClientID == "" {
			slog.Error("OIDC_ISSUER and OIDC_CLIENT_ID are required for OIDC auth")
			os.Exit(1)
		}

		var oidcScopes []string
		if scopes := os.Getenv("OIDC_SCOPES"); scopes != "" {
			oidcScopes = strings.Split(scopes, ",")
		}

		provider, err := oidc.NewProvider(oidc.Config{
			IssuerURL:    oidcIssuer,
			ClientID:     oidcClientID,
			ClientSecret: oidcClientSecret,
			RedirectURL:  oidcRedirectURL,
			Scopes:       oidcScopes,
		})
		if err != nil {
			slog.Error("Failed to create OIDC provider", "error", err)
			os.Exit(1)
		}
		authProvider = provider

	default:
		slog.Error("Unknown AUTH_METHOD", "method", authMethod)
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
	oauthHandler := oauth.NewHandler(baseURL, authProvider, db, privateKey, vapidConfig)
	oauthHandler.RegisterRoutes(mux)

	mux.HandleFunc("/{path...}", func(w http.ResponseWriter, r *http.Request) {
		slog.Warn("Not found", "method", r.Method, "path", r.URL.Path)
		http.NotFound(w, r)
	})

	slog.Info("Starting server", "port", port, "auth_method", authMethod)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		slog.Error("Server failed", "error", err)
		os.Exit(1)
	}
}
