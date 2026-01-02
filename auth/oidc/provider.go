// Package oidc implements OpenID Connect authentication
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ahyattdev/minimal-fxa-server/auth"
	"github.com/ahyattdev/minimal-fxa-server/database"
	"gorm.io/gorm"
)

// Provider implements OIDC authentication
type Provider struct {
	config    Config
	client    *http.Client
	db        *gorm.DB
	oidcMeta  *OIDCMetadata
	metaMutex sync.RWMutex
}

// Config holds OIDC provider configuration
type Config struct {
	// DB is the database connection for storing OIDC states
	DB *gorm.DB
	// IssuerURL is the OIDC issuer URL (e.g., https://accounts.google.com)
	IssuerURL string
	// ClientID is the OAuth client ID
	ClientID string
	// ClientSecret is the OAuth client secret
	ClientSecret string
	// RedirectURL is the callback URL for this application
	RedirectURL string
	// Scopes to request (default: openid email profile)
	Scopes []string
}

// OIDCMetadata holds the discovered OIDC configuration
type OIDCMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JwksURI               string `json:"jwks_uri"`
}

// TokenResponse is the response from the token endpoint
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// UserInfo is the response from the userinfo endpoint
type UserInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name,omitempty"`
}

// NewProvider creates a new OIDC authentication provider
func NewProvider(cfg Config) (*Provider, error) {
	if cfg.DB == nil {
		return nil, fmt.Errorf("database connection is required")
	}
	if cfg.IssuerURL == "" {
		return nil, fmt.Errorf("OIDC issuer URL is required")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("OIDC client ID is required")
	}
	if cfg.RedirectURL == "" {
		return nil, fmt.Errorf("OIDC redirect URL is required")
	}

	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "email", "profile"}
	}

	p := &Provider{
		config: cfg,
		client: &http.Client{Timeout: 10 * time.Second},
		db:     cfg.DB,
	}

	// Discover OIDC metadata
	if err := p.discover(); err != nil {
		return nil, fmt.Errorf("OIDC discovery failed: %w", err)
	}

	return p, nil
}

// discover fetches the OIDC discovery document
func (p *Provider) discover() error {
	discoveryURL := strings.TrimSuffix(p.config.IssuerURL, "/") + "/.well-known/openid-configuration"

	resp, err := p.client.Get(discoveryURL)
	if err != nil {
		return fmt.Errorf("failed to fetch discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("discovery endpoint returned %d", resp.StatusCode)
	}

	var meta OIDCMetadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return fmt.Errorf("failed to decode discovery document: %w", err)
	}

	p.metaMutex.Lock()
	p.oidcMeta = &meta
	p.metaMutex.Unlock()

	slog.Info("OIDC discovery complete", "issuer", meta.Issuer, "auth_endpoint", meta.AuthorizationEndpoint)
	return nil
}

// Type returns the provider type
func (p *Provider) Type() string {
	return "oidc"
}

// Authenticate is not used for OIDC (uses redirect flow)
func (p *Provider) Authenticate(ctx context.Context, username, password string) (*auth.User, error) {
	return nil, fmt.Errorf("OIDC does not support direct authentication - use HandleLogin for redirect")
}

// HandleLogin redirects to the OIDC provider
func (p *Provider) HandleLogin(w http.ResponseWriter, r *http.Request) {
	p.metaMutex.RLock()
	meta := p.oidcMeta
	p.metaMutex.RUnlock()

	if meta == nil {
		http.Error(w, "OIDC not configured", http.StatusInternalServerError)
		return
	}

	// Generate state for CSRF protection
	stateBytes := make([]byte, 32)
	rand.Read(stateBytes)
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	// Store state in database for CSRF protection
	oidcState := &database.OIDCState{
		State:     state,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	if err := p.db.Create(oidcState).Error; err != nil {
		slog.Error("Failed to store OIDC state", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Build authorization URL
	authURL, _ := url.Parse(meta.AuthorizationEndpoint)
	q := authURL.Query()
	q.Set("client_id", p.config.ClientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", p.config.RedirectURL)
	q.Set("scope", strings.Join(p.config.Scopes, " "))
	q.Set("state", state)
	authURL.RawQuery = q.Encode()

	http.Redirect(w, r, authURL.String(), http.StatusFound)
}

// HandleCallback processes the OIDC callback
func (p *Provider) HandleCallback(w http.ResponseWriter, r *http.Request) (*auth.User, error) {
	// Check for errors from provider
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		errDesc := r.URL.Query().Get("error_description")
		return nil, fmt.Errorf("OIDC error: %s - %s", errParam, errDesc)
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" {
		return nil, fmt.Errorf("missing authorization code")
	}

	// Verify and consume state from database
	var oidcState database.OIDCState
	result := p.db.Where("state = ? AND expires_at > ?", state, time.Now()).First(&oidcState)
	if result.Error != nil {
		return nil, fmt.Errorf("invalid or expired state parameter")
	}
	// Delete the state to prevent reuse
	p.db.Delete(&oidcState)

	p.metaMutex.RLock()
	meta := p.oidcMeta
	p.metaMutex.RUnlock()

	// Exchange code for tokens
	tokenResp, err := p.exchangeCode(code, meta.TokenEndpoint)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}

	// Get user info
	userInfo, err := p.getUserInfo(tokenResp.AccessToken, meta.UserinfoEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Generate user ID from OIDC subject
	idHash := sha256.Sum256([]byte(p.config.IssuerURL + ":" + userInfo.Sub))
	userID := fmt.Sprintf("%x", idHash)[:32]

	user := &auth.User{
		ID:       userID,
		Email:    userInfo.Email,
		Verified: userInfo.EmailVerified,
	}

	slog.Info("OIDC user authenticated", "email", user.Email, "userID", user.ID, "sub", userInfo.Sub)
	return user, nil
}

// exchangeCode exchanges the authorization code for tokens
func (p *Provider) exchangeCode(code, tokenEndpoint string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {p.config.RedirectURL},
		"client_id":     {p.config.ClientID},
		"client_secret": {p.config.ClientSecret},
	}

	resp, err := p.client.PostForm(tokenEndpoint, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned %d", resp.StatusCode)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

// getUserInfo fetches user information from the userinfo endpoint
func (p *Provider) getUserInfo(accessToken, userinfoEndpoint string) (*UserInfo, error) {
	req, err := http.NewRequest("GET", userinfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo endpoint returned %d", resp.StatusCode)
	}

	var userInfo UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}

// GetUserByID is not fully supported for OIDC (would need to cache user info)
func (p *Provider) GetUserByID(ctx context.Context, id string) (*auth.User, error) {
	// OIDC doesn't have a way to look up users by ID without caching
	// The user info is only available during the callback
	return nil, auth.ErrUserNotFound{ID: id}
}
