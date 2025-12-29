package autoconfig

import (
	"encoding/json"
	"net/http"
)

type ClientConfiguration struct {
	AuthServerBaseURL    string `json:"auth_server_base_url"`
	OAuthServerBaseURL   string `json:"oauth_server_base_url"`
	ProfileServerBaseURL string `json:"profile_server_base_url"`
	TokenServerBaseURL   string `json:"sync_tokenserver_base_url"`
	PairingServerBaseURL string `json:"pairing_server_base_url,omitempty"`
}

type Handler struct {
	Config ClientConfiguration
}

func NewHandler(baseURL, syncServerURL string) *Handler {
	return &Handler{
		Config: ClientConfiguration{
			AuthServerBaseURL:    baseURL + "/auth",
			OAuthServerBaseURL:   baseURL + "/oauth",
			ProfileServerBaseURL: baseURL + "/profile",
			TokenServerBaseURL:   syncServerURL,
		},
	}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/fxa-client-configuration", h.handleClientConfiguration)
}

func (h *Handler) handleClientConfiguration(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.Config)
}
