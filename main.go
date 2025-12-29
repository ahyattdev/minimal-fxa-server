package main

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/ahyattdev/minimal-fxa-server/autoconfig"
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

	mux := http.NewServeMux()

	autoconfigHandler := autoconfig.NewHandler(baseURL, syncServerURL)
	autoconfigHandler.RegisterRoutes(mux)

	oauthHandler := oauth.NewHandler(baseURL, "username", "password")
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
