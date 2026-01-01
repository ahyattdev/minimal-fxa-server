package oauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/SherClockHolmes/webpush-go"
	"github.com/ahyattdev/minimal-fxa-server/database"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

// VAPIDConfig holds Web Push VAPID configuration
type VAPIDConfig struct {
	PrivateKey string // Base64url-encoded private key
	PublicKey  string // Base64url-encoded public key
	Subscriber string // Contact email (mailto:...)
}

type Handler struct {
	baseURL       string
	username      string
	password      string
	db            *gorm.DB
	privateKey    *rsa.PrivateKey
	keyID         string
	loginTemplate *template.Template
	vapid         VAPIDConfig
}

func NewHandler(baseURL, username, password string, db *gorm.DB, privateKey *rsa.PrivateKey, vapid VAPIDConfig) *Handler {
	// Generate a key ID from the public key modulus
	keyIDHash := sha256.Sum256(privateKey.PublicKey.N.Bytes())
	keyID := base64.RawURLEncoding.EncodeToString(keyIDHash[:8])

	return &Handler{
		baseURL:       baseURL,
		username:      username,
		password:      password,
		db:            db,
		privateKey:    privateKey,
		keyID:         keyID,
		loginTemplate: template.Must(template.New("login").Parse(loginHTML)),
		vapid:         vapid,
	}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", h.handleAuthorizePage)
	mux.HandleFunc("POST /{$}", h.handleLogin)
	mux.HandleFunc("POST /oauth/v1/token", h.handleToken)
	mux.HandleFunc("POST /oauth/v1/verify", h.handleVerify)
	mux.HandleFunc("GET /oauth/v1/jwks", h.handleJWKS)

	// Auth server endpoints
	mux.HandleFunc("POST /auth/v1/oauth/token", h.handleAuthToken)
	mux.HandleFunc("POST /auth/v1/account/device", h.handleDevice)
	mux.HandleFunc("GET /auth/v1/account/devices", h.handleDevices)
	mux.HandleFunc("POST /auth/v1/account/devices/notify", h.handleDevicesNotify)
	mux.HandleFunc("GET /auth/v1/account/device/commands", h.handleDeviceCommands)
	mux.HandleFunc("GET /auth/v1/account/attached_clients", h.handleAttachedClients)
	mux.HandleFunc("GET /auth/v1/recovery_email/status", h.handleRecoveryEmailStatus)
	mux.HandleFunc("POST /auth/v1/account/keys", h.handleAccountKeys)
	mux.HandleFunc("POST /auth/v1/session/destroy", h.handleSessionDestroy)
	mux.HandleFunc("POST /auth/v1/oauth/destroy", h.handleOAuthDestroy)

	// Profile server endpoints
	mux.HandleFunc("GET /profile/v1/profile", h.handleProfile)
}

func (h *Handler) handleAuthorizePage(w http.ResponseWriter, r *http.Request) {
	data := map[string]string{
		"ClientID":            r.URL.Query().Get("client_id"),
		"State":               r.URL.Query().Get("state"),
		"CodeChallenge":       r.URL.Query().Get("code_challenge"),
		"CodeChallengeMethod": r.URL.Query().Get("code_challenge_method"),
		"Scope":               r.URL.Query().Get("scope"),
		"KeysJWK":             r.URL.Query().Get("keys_jwk"),
		"AccessType":          r.URL.Query().Get("access_type"),
	}
	h.loginTemplate.Execute(w, data)
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if username != h.username || password != h.password {
		slog.Warn("Failed login attempt", "username", username)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Generate OAuth authorization code
	code := generateHexString(64)
	state := r.FormValue("state")
	userID := fmt.Sprintf("%x", sha256.Sum256([]byte(h.username)))[:32]

	slog.Info("User authenticated, generated auth code", "username", username)

	// Store the auth code in database
	authCode := &database.AuthCode{
		Code:                code,
		ClientID:            r.FormValue("client_id"),
		CodeChallenge:       r.FormValue("code_challenge"),
		CodeChallengeMethod: r.FormValue("code_challenge_method"),
		State:               state,
		KeysJWK:             r.FormValue("keys_jwk"),
		UserID:              userID,
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}
	if err := h.db.Create(authCode).Error; err != nil {
		slog.Error("Failed to store auth code", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Generate a session token for this login
	sessionToken := generateHexString(64)

	// Store session in database
	session := &database.Session{
		ID:           sessionToken,
		UserID:       userID,
		CreatedAt:    time.Now(),
		LastAccessAt: time.Now(),
	}
	if err := h.db.Create(session).Error; err != nil {
		slog.Error("Failed to store session", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Prepare OAuth data (for fxaccounts:oauth_login)
	// Firefox expects these fields for OAuth login
	oauthData := map[string]any{
		"code":                code,
		"state":               state,
		"redirect":            "web",
		"action":              "signin",
		"uid":                 userID,
		"email":               h.username + "@localhost",
		"verified":            true,
		"sessionToken":        sessionToken,
		"declinedSyncEngines": []string{},
		"offeredSyncEngines":  []string{"bookmarks", "history", "passwords", "tabs", "addons", "preferences"},
	}
	oauthJSON, _ := json.Marshal(oauthData)

	// Prepare login data (for fxaccounts:login - sets up user in Firefox)
	loginData := map[string]any{
		"uid":          userID,
		"email":        h.username + "@localhost",
		"sessionToken": sessionToken,
		"verified":     true,
	}
	loginJSON, _ := json.Marshal(loginData)

	w.Header().Set("Content-Type", "text/html")
	html := `<!DOCTYPE html>
<html>
<head><title>Signing in...</title></head>
<body>
<p id="status">Signing in...</p>
<script>
(function() {
  const status = document.getElementById('status');
  const loginData = ` + string(loginJSON) + `;
  const oauthData = ` + string(oauthJSON) + `;
  
  function sendWebChannel(command, payload, messageId) {
    if (!messageId) {
      messageId = Date.now().toString(36) + '-' + Math.random().toString(36).substr(2);
    }
    const detail = {
      id: 'account_updates',
      message: {
        command: command,
        messageId: messageId,
        data: payload
      }
    };
    console.log('[FxA] Sending:', command, detail);
    window.dispatchEvent(new CustomEvent('WebChannelMessageToChrome', {
      detail: JSON.stringify(detail)
    }));
    return messageId;
  }
  
  let loginAcknowledged = false;
  
  // Listen for responses from Firefox
  window.addEventListener('WebChannelMessageToContent', function(e) {
    console.log('[FxA] Received from Firefox:', e.detail);
    let detail = e.detail;
    if (typeof detail === 'string') {
      try { detail = JSON.parse(detail); } catch(err) { return; }
    }
    const cmd = detail.message?.command;
    const msgId = detail.message?.messageId;
    const data = detail.message?.data;
    
    if (cmd === 'fxaccounts:can_link_account') {
      sendWebChannel('fxaccounts:can_link_account', { ok: true }, msgId);
    } else if (cmd === 'fxaccounts:login' && !data?.error) {
      // Firefox acknowledged the login, now send OAuth
      console.log('[FxA] Login acknowledged, sending OAuth login');
      loginAcknowledged = true;
      sendWebChannel('fxaccounts:oauth_login', oauthData);
      console.log('[FxA] OAuth login sent with data:', oauthData);
    } else if (cmd === 'fxaccounts:oauth_login' && !data?.error) {
      status.textContent = 'Sign-in complete! You can close this tab.';
    }
  });
  
  status.textContent = 'Setting up account...';
  
  // Step 1: Send fxaccounts:login to set up user data in Firefox
  console.log('[FxA] Sending login data:', loginData);
  sendWebChannel('fxaccounts:login', loginData);
  
  // Fallback: if login doesn't get acknowledged within 2 seconds, try OAuth anyway
  setTimeout(function() {
    if (!loginAcknowledged) {
      console.log('[FxA] Login not acknowledged, trying OAuth anyway');
      sendWebChannel('fxaccounts:oauth_login', oauthData);
    }
  }, 2000);
})();
</script>
</body>
</html>`
	w.Write([]byte(html))
}

func (h *Handler) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	code := r.FormValue("code")

	var authCode database.AuthCode
	var oauthToken *database.OAuthToken
	refreshToken := generateRandomString(64)
	scope := "https://identity.mozilla.com/apps/oldsync profile"
	expiresAt := time.Now().Add(time.Hour)

	// Use transaction to atomically consume auth code and create token
	err := h.db.Transaction(func(tx *gorm.DB) error {
		// Find and lock the auth code
		result := tx.Where("code = ? AND expires_at > ?", code, time.Now()).First(&authCode)
		if result.Error != nil {
			return result.Error
		}

		// Delete the auth code immediately to prevent reuse
		if err := tx.Delete(&authCode).Error; err != nil {
			return err
		}

		// Get or create user to get stable keysChangedAt
		keysChangedAt, err := h.getOrCreateUser(tx, authCode.UserID)
		if err != nil {
			return fmt.Errorf("failed to get/create user: %w", err)
		}

		// Generate JWT access token
		accessToken, err := h.generateAccessToken(authCode.UserID, authCode.ClientID, scope, expiresAt, keysChangedAt)
		if err != nil {
			return fmt.Errorf("failed to generate access token: %w", err)
		}

		// Create the OAuth token
		oauthToken = &database.OAuthToken{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			UserID:       authCode.UserID,
			ClientID:     authCode.ClientID,
			Scope:        scope,
			CreatedAt:    time.Now(),
			ExpiresAt:    expiresAt,
		}
		if err := tx.Create(oauthToken).Error; err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		slog.Warn("Token exchange failed", "code", code, "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		return
	}

	response := map[string]any{
		"access_token":  oauthToken.AccessToken,
		"token_type":    "bearer",
		"expires_in":    3600,
		"refresh_token": oauthToken.RefreshToken,
		"scope":         oauthToken.Scope,
	}

	// Generate keys_jwe if keys_jwk was provided
	if authCode.KeysJWK != "" {
		keysJWE, err := generateScopedKeysJWE(authCode.KeysJWK)
		if err != nil {
			slog.Warn("Failed to generate keys_jwe", "error", err)
		} else {
			response["keys_jwe"] = keysJWE
			slog.Info("Generated keys_jwe for sync")
		}
	}

	slog.Info("Token issued (JWT)", "client_id", oauthToken.ClientID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Warn("Failed to decode verify request", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request"})
		return
	}

	slog.Info("Token verify request", "has_token", req.Token != "")

	if req.Token == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request"})
		return
	}

	// Try to verify as JWT first (cryptographically secure)
	claims, err := h.verifyAccessToken(req.Token)
	if err == nil {
		// JWT verified successfully
		userID, _ := claims["sub"].(string)
		clientID, _ := claims["client_id"].(string)
		scope, _ := claims["scope"].(string)
		exp, _ := claims["exp"].(float64)
		generation, _ := claims["fxa-generation"].(float64)

		expiresIn := int(exp - float64(time.Now().Unix()))
		if expiresIn < 0 {
			slog.Warn("JWT token expired")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_token"})
			return
		}

		response := map[string]any{
			"user":       userID,
			"client_id":  clientID,
			"scope":      strings.Split(scope, " "),
			"generation": int64(generation),
		}

		slog.Info("JWT token verified", "user", userID, "scope", scope)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	slog.Info("JWT verification failed, trying database lookup", "error", err)

	// Fallback: Look up the token in database (for legacy opaque tokens)
	var oauthToken database.OAuthToken
	if err := h.db.Where("access_token = ?", req.Token).First(&oauthToken).Error; err != nil {
		slog.Warn("Token not found for verify", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_token"})
		return
	}

	// Check if token is expired
	if time.Now().After(oauthToken.ExpiresAt) {
		slog.Warn("Token expired")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_token"})
		return
	}

	// Return token info
	response := map[string]any{
		"user":       oauthToken.UserID,
		"client_id":  oauthToken.ClientID,
		"scope":      strings.Split(oauthToken.Scope, " "),
		"generation": oauthToken.CreatedAt.Unix(),
	}

	slog.Info("Token verified via database", "user", oauthToken.UserID, "scope", oauthToken.Scope)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) handleJWKS(w http.ResponseWriter, r *http.Request) {
	slog.Info("JWKS request")

	// Return the public key in JWK format (RSA)
	pubKey := &h.privateKey.PublicKey

	jwk := map[string]any{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(bigIntToBytes(pubKey.E)),
		"kid": h.keyID,
		"use": "sig",
		"alg": "RS256",
	}

	response := map[string]any{
		"keys": []any{jwk},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// bigIntToBytes converts an int (RSA exponent) to bytes
func bigIntToBytes(e int) []byte {
	// RSA public exponent is typically 65537 (0x10001)
	if e == 65537 {
		return []byte{0x01, 0x00, 0x01}
	}
	// Handle other cases
	result := make([]byte, 0)
	for e > 0 {
		result = append([]byte{byte(e & 0xff)}, result...)
		e >>= 8
	}
	return result
}

// getOrCreateUser ensures a user exists and returns their keysChangedAt timestamp
func (h *Handler) getOrCreateUser(tx *gorm.DB, userID string) (int64, error) {
	var user database.User
	result := tx.Where("id = ?", userID).First(&user)
	if result.Error == nil {
		return user.KeysChangedAt, nil
	}
	if result.Error != gorm.ErrRecordNotFound {
		return 0, result.Error
	}

	// User doesn't exist, create with current timestamp as keysChangedAt
	user = database.User{
		ID:            userID,
		KeysChangedAt: time.Now().Unix(),
		CreatedAt:     time.Now(),
	}
	if err := tx.Create(&user).Error; err != nil {
		return 0, err
	}
	slog.Info("Created new user", "userID", userID, "keysChangedAt", user.KeysChangedAt)
	return user.KeysChangedAt, nil
}

// generateAccessToken creates a signed JWT access token
func (h *Handler) generateAccessToken(userID, clientID, scope string, expiresAt time.Time, keysChangedAt int64) (string, error) {
	// Generate a unique JWT ID to prevent duplicate tokens
	jti := generateRandomString(16)

	claims := jwt.MapClaims{
		"iss":            h.baseURL, // Issuer - required for JWT verification
		"sub":            userID,
		"aud":            clientID, // Audience - the client this token is for
		"client_id":      clientID,
		"scope":          scope,
		"iat":            time.Now().Unix(),
		"exp":            expiresAt.Unix(),
		"jti":            jti,           // Unique token ID to prevent duplicates
		"fxa-generation": keysChangedAt, // Must be stable per user for syncstorage-rs
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = h.keyID
	token.Header["typ"] = "at+jwt" // Required by syncstorage-rs

	return token.SignedString(h.privateKey)
}

// verifyAccessToken validates a JWT and returns its claims
func (h *Handler) verifyAccessToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return &h.privateKey.PublicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func (h *Handler) handleAuthToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code         string `json:"code"`
		ClientID     string `json:"client_id"`
		CodeVerifier string `json:"code_verifier"`
		GrantType    string `json:"grant_type"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
		TTL          int    `json:"ttl"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Warn("Failed to decode token request", "error", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	slog.Info("Token exchange request",
		"grant_type", req.GrantType,
		"client_id", req.ClientID,
		"has_code", req.Code != "",
		"has_refresh_token", req.RefreshToken != "",
		"scope", req.Scope)

	// Handle fxa-credentials grant type (Mozilla-specific)
	// Firefox uses this to get access tokens using session credentials
	if req.GrantType == "fxa-credentials" {
		userID := fmt.Sprintf("%x", sha256.Sum256([]byte(h.username)))[:32]

		scope := req.Scope
		if scope == "" {
			scope = "profile"
		}

		ttl := req.TTL
		if ttl <= 0 {
			ttl = 3600
		}

		expiresAt := time.Now().Add(time.Duration(ttl) * time.Second)

		var oauthToken *database.OAuthToken
		err := h.db.Transaction(func(tx *gorm.DB) error {
			// Get or create user to get stable keysChangedAt
			keysChangedAt, err := h.getOrCreateUser(tx, userID)
			if err != nil {
				return fmt.Errorf("failed to get/create user: %w", err)
			}

			// Generate JWT access token
			accessToken, err := h.generateAccessToken(userID, req.ClientID, scope, expiresAt, keysChangedAt)
			if err != nil {
				return fmt.Errorf("failed to generate access token: %w", err)
			}

			// Store the token in database
			oauthToken = &database.OAuthToken{
				AccessToken:  accessToken,
				RefreshToken: generateRandomString(64), // Generate one for potential future use
				UserID:       userID,
				ClientID:     req.ClientID,
				Scope:        scope,
				CreatedAt:    time.Now(),
				ExpiresAt:    expiresAt,
			}
			return tx.Create(oauthToken).Error
		})
		if err != nil {
			slog.Error("Failed to create token for fxa-credentials", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		response := map[string]any{
			"access_token": oauthToken.AccessToken,
			"token_type":   "bearer",
			"expires_in":   ttl,
			"scope":        scope,
		}

		slog.Info("Issued fxa-credentials token (JWT)", "scope", scope, "ttl", ttl)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	// Handle refresh token grant - check both grant_type and presence of refresh_token
	if req.GrantType == "refresh_token" || (req.RefreshToken != "" && req.Code == "") {
		if req.RefreshToken == "" {
			slog.Warn("Empty refresh_token in token request")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request"})
			return
		}

		slog.Info("Processing refresh token request")

		var newAccessToken string
		var scope string
		expiresAt := time.Now().Add(time.Hour)

		// Use transaction to atomically update the token
		err := h.db.Transaction(func(tx *gorm.DB) error {
			var existingToken database.OAuthToken
			if err := tx.Where("refresh_token = ?", req.RefreshToken).First(&existingToken).Error; err != nil {
				return err
			}

			scope = req.Scope
			if scope == "" {
				scope = existingToken.Scope
			}

			// Get or create user to get stable keysChangedAt
			keysChangedAt, err := h.getOrCreateUser(tx, existingToken.UserID)
			if err != nil {
				return fmt.Errorf("failed to get/create user: %w", err)
			}

			// Generate JWT access token
			newAccessToken, err = h.generateAccessToken(existingToken.UserID, existingToken.ClientID, scope, expiresAt, keysChangedAt)
			if err != nil {
				return fmt.Errorf("failed to generate access token: %w", err)
			}

			existingToken.AccessToken = newAccessToken
			existingToken.ExpiresAt = expiresAt
			return tx.Save(&existingToken).Error
		})

		if err != nil {
			slog.Warn("Token refresh failed", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}

		response := map[string]any{
			"access_token": newAccessToken,
			"token_type":   "bearer",
			"expires_in":   3600,
			"scope":        scope,
		}

		slog.Info("Token refreshed (JWT)", "scope", scope)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	// Handle authorization code grant
	if req.Code == "" {
		slog.Warn("Empty code in token request")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request"})
		return
	}

	var authCode database.AuthCode
	var oauthToken *database.OAuthToken
	refreshToken := generateRandomString(64)
	scope := "https://identity.mozilla.com/apps/oldsync profile"
	expiresAt := time.Now().Add(time.Hour)

	// Use transaction to atomically consume auth code and create token
	err := h.db.Transaction(func(tx *gorm.DB) error {
		// Find and lock the auth code
		if err := tx.Where("code = ? AND expires_at > ?", req.Code, time.Now()).First(&authCode).Error; err != nil {
			return err
		}

		// Delete the auth code immediately to prevent reuse
		if err := tx.Delete(&authCode).Error; err != nil {
			return err
		}

		// Get or create user to get stable keysChangedAt
		keysChangedAt, err := h.getOrCreateUser(tx, authCode.UserID)
		if err != nil {
			return fmt.Errorf("failed to get/create user: %w", err)
		}

		// Generate JWT access token
		accessToken, err := h.generateAccessToken(authCode.UserID, authCode.ClientID, scope, expiresAt, keysChangedAt)
		if err != nil {
			return fmt.Errorf("failed to generate access token: %w", err)
		}

		// Create the OAuth token
		oauthToken = &database.OAuthToken{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			UserID:       authCode.UserID,
			ClientID:     authCode.ClientID,
			Scope:        scope,
			CreatedAt:    time.Now(),
			ExpiresAt:    expiresAt,
		}
		return tx.Create(oauthToken).Error
	})

	if err != nil {
		slog.Warn("Token exchange failed", "code", req.Code, "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		return
	}

	response := map[string]any{
		"access_token":  oauthToken.AccessToken,
		"refresh_token": oauthToken.RefreshToken,
		"token_type":    "bearer",
		"expires_in":    3600,
		"scope":         oauthToken.Scope,
	}

	// Generate keys_jwe if keys_jwk was provided
	if authCode.KeysJWK != "" {
		keysJWE, err := generateScopedKeysJWE(authCode.KeysJWK)
		if err != nil {
			slog.Warn("Failed to generate keys_jwe", "error", err)
		} else {
			response["keys_jwe"] = keysJWE
			slog.Info("Generated keys_jwe for sync")
		}
	}

	slog.Info("Token issued (JWT)", "client_id", oauthToken.ClientID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) handleDevice(w http.ResponseWriter, r *http.Request) {
	slog.Info("Device registration request")

	userID := fmt.Sprintf("%x", sha256.Sum256([]byte(h.username)))[:32]

	// Get access token from Authorization header
	var accessToken string
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		accessToken = strings.TrimPrefix(authHeader, "Bearer ")
	}

	// Parse request body for device info
	var req struct {
		Name          string  `json:"name"`
		Type          string  `json:"type"`
		PushCallback  *string `json:"pushCallback"`
		PushPublicKey *string `json:"pushPublicKey"`
		PushAuthKey   *string `json:"pushAuthKey"`
	}
	// Ignore decode errors - use defaults if body is empty/invalid
	_ = json.NewDecoder(r.Body).Decode(&req)

	if req.Name == "" {
		req.Name = "Firefox"
	}
	if req.Type == "" {
		req.Type = "desktop"
	}

	deviceID := generateRandomString(32)

	// Store device and link to OAuth token in a transaction
	device := &database.Device{
		ID:            deviceID,
		UserID:        userID,
		Name:          req.Name,
		Type:          req.Type,
		PushCallback:  req.PushCallback,
		PushPublicKey: req.PushPublicKey,
		PushAuthKey:   req.PushAuthKey,
		CreatedAt:     time.Now(),
		LastAccessAt:  time.Now(),
	}

	err := h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(device).Error; err != nil {
			return err
		}

		// Link device to the OAuth token used for this request
		if accessToken != "" {
			if err := tx.Model(&database.OAuthToken{}).
				Where("access_token = ?", accessToken).
				Update("device_id", deviceID).Error; err != nil {
				return err
			}
		}

		return nil
	})

	if err != nil {
		slog.Error("Failed to create device", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	response := map[string]any{
		"id":            deviceID,
		"name":          device.Name,
		"type":          device.Type,
		"pushCallback":  device.PushCallback,
		"pushPublicKey": device.PushPublicKey,
		"pushAuthKey":   device.PushAuthKey,
		"createdAt":     device.CreatedAt.UnixMilli(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) handleDevices(w http.ResponseWriter, r *http.Request) {
	slog.Info("Device list request")

	userID := fmt.Sprintf("%x", sha256.Sum256([]byte(h.username)))[:32]

	// Find current device from the access token
	var currentDeviceID string
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		accessToken := strings.TrimPrefix(authHeader, "Bearer ")
		var token database.OAuthToken
		if err := h.db.Where("access_token = ?", accessToken).First(&token).Error; err == nil && token.DeviceID != nil {
			currentDeviceID = *token.DeviceID
		}
	}

	// Get devices from database
	var devices []database.Device
	if err := h.db.Where("user_id = ?", userID).Find(&devices).Error; err != nil {
		slog.Error("Failed to fetch devices", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Convert to response format
	result := make([]map[string]any, len(devices))
	for i, device := range devices {
		result[i] = map[string]any{
			"id":              device.ID,
			"name":            device.Name,
			"type":            device.Type,
			"isCurrentDevice": device.ID == currentDeviceID,
			"pushCallback":    device.PushCallback,
			"pushPublicKey":   device.PushPublicKey,
			"pushAuthKey":     device.PushAuthKey,
			"createdAt":       device.CreatedAt.UnixMilli(),
			"lastAccessTime":  device.LastAccessAt.UnixMilli(),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (h *Handler) handleDeviceCommands(w http.ResponseWriter, r *http.Request) {
	slog.Info("Device commands request")

	// Return empty commands list - we don't store commands server-side
	// Commands are delivered via push notifications in real-time
	response := map[string]any{
		"index":    0,
		"last":     true,
		"messages": []any{},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) handleDevicesNotify(w http.ResponseWriter, r *http.Request) {
	slog.Info("Device notify request")

	// Check if VAPID is configured
	if h.vapid.PrivateKey == "" || h.vapid.PublicKey == "" {
		slog.Warn("Push notifications not configured - VAPID keys missing")
		// Return success anyway - Firefox doesn't require this to work
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{})
		return
	}

	userID := fmt.Sprintf("%x", sha256.Sum256([]byte(h.username)))[:32]

	// Parse request body
	var req struct {
		To       any             `json:"to"`       // "all" or array of device IDs
		Excluded []string        `json:"excluded"` // Device IDs to exclude
		Payload  json.RawMessage `json:"payload"`  // Encrypted payload to send
		TTL      int             `json:"TTL"`      // Time-to-live in seconds
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Warn("Invalid notify request body", "error", err)
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	// Get current device ID from the access token (to exclude self)
	var currentDeviceID string
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		accessToken := strings.TrimPrefix(authHeader, "Bearer ")
		var token database.OAuthToken
		if err := h.db.Where("access_token = ?", accessToken).First(&token).Error; err == nil && token.DeviceID != nil {
			currentDeviceID = *token.DeviceID
		}
	}

	// Get target devices
	var devices []database.Device
	if err := h.db.Where("user_id = ?", userID).Find(&devices).Error; err != nil {
		slog.Error("Failed to fetch devices for notify", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Build exclusion set
	excluded := make(map[string]bool)
	for _, id := range req.Excluded {
		excluded[id] = true
	}
	// Always exclude the current device
	if currentDeviceID != "" {
		excluded[currentDeviceID] = true
	}

	// Determine which devices to notify
	var targetDeviceIDs map[string]bool
	switch to := req.To.(type) {
	case string:
		if to == "all" {
			targetDeviceIDs = nil // nil means all
		}
	case []any:
		targetDeviceIDs = make(map[string]bool)
		for _, id := range to {
			if idStr, ok := id.(string); ok {
				targetDeviceIDs[idStr] = true
			}
		}
	}

	// Send push notifications
	successCount := 0
	for _, device := range devices {
		// Skip if excluded
		if excluded[device.ID] {
			continue
		}
		// Skip if not in target list (when specific targets provided)
		if targetDeviceIDs != nil && !targetDeviceIDs[device.ID] {
			continue
		}
		// Skip if no push subscription
		if device.PushCallback == nil || *device.PushCallback == "" {
			continue
		}

		// Send push notification
		if err := h.sendPushNotification(device, req.Payload, req.TTL); err != nil {
			slog.Warn("Failed to send push notification", "deviceID", device.ID, "error", err)
		} else {
			successCount++
		}
	}

	slog.Info("Push notifications sent", "count", successCount)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{})
}

func (h *Handler) sendPushNotification(device database.Device, payload json.RawMessage, ttl int) error {
	if device.PushCallback == nil || device.PushPublicKey == nil || device.PushAuthKey == nil {
		return fmt.Errorf("device missing push subscription info")
	}

	subscription := &webpush.Subscription{
		Endpoint: *device.PushCallback,
		Keys: webpush.Keys{
			P256dh: *device.PushPublicKey,
			Auth:   *device.PushAuthKey,
		},
	}

	options := &webpush.Options{
		Subscriber:      h.vapid.Subscriber,
		VAPIDPublicKey:  h.vapid.PublicKey,
		VAPIDPrivateKey: h.vapid.PrivateKey,
		TTL:             ttl,
	}

	resp, err := webpush.SendNotification(payload, subscription, options)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("push service returned %d", resp.StatusCode)
	}

	return nil
}

func (h *Handler) handleAttachedClients(w http.ResponseWriter, r *http.Request) {
	slog.Info("Attached clients request")

	userID := fmt.Sprintf("%x", sha256.Sum256([]byte(h.username)))[:32]

	// Extract current access token from Authorization header
	var currentAccessToken string
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		currentAccessToken = strings.TrimPrefix(authHeader, "Bearer ")
	}

	// Get OAuth tokens from database
	var tokens []database.OAuthToken
	if err := h.db.Where("user_id = ?", userID).Find(&tokens).Error; err != nil {
		slog.Error("Failed to fetch attached clients", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Convert to response format
	clients := make([]map[string]any, len(tokens))
	for i, token := range tokens {
		clients[i] = map[string]any{
			"clientId":         token.ClientID,
			"deviceId":         token.DeviceID,
			"sessionTokenId":   nil,
			"refreshTokenId":   fmt.Sprintf("%d", token.ID),
			"isCurrentSession": token.AccessToken == currentAccessToken,
			"deviceType":       "desktop",
			"name":             "Firefox",
			"createdTime":      token.CreatedAt.UnixMilli(),
			"lastAccessTime":   token.ExpiresAt.UnixMilli(),
			"scope":            strings.Split(token.Scope, " "),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(clients)
}

func (h *Handler) handleRecoveryEmailStatus(w http.ResponseWriter, r *http.Request) {
	slog.Info("Recovery email status request")

	response := map[string]any{
		"email":           h.username + "@localhost",
		"verified":        true,
		"sessionVerified": true,
		"emailVerified":   true,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) handleAccountKeys(w http.ResponseWriter, r *http.Request) {
	slog.Info("Account keys request")

	// Generate placeholder keys (in reality these need proper crypto)
	kA := generateRandomString(64)
	wrapKB := generateRandomString(64)

	response := map[string]any{
		"kA":     kA,
		"wrapKB": wrapKB,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) handleSessionDestroy(w http.ResponseWriter, r *http.Request) {
	slog.Info("Session destroy request")
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("{}"))
}

func (h *Handler) handleOAuthDestroy(w http.ResponseWriter, r *http.Request) {
	slog.Info("OAuth destroy request")
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("{}"))
}

func (h *Handler) handleProfile(w http.ResponseWriter, r *http.Request) {
	slog.Info("Profile request")

	// Use a consistent UID based on username
	uid := fmt.Sprintf("%x", sha256.Sum256([]byte(h.username)))[:32]

	response := map[string]any{
		"uid":                     uid,
		"email":                   h.username + "@localhost",
		"displayName":             h.username,
		"avatar":                  nil,
		"avatarDefault":           true,
		"amrValues":               []string{"pwd"},
		"twoFactorAuthentication": false,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func generateRandomString(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)[:length]
}

func generateHexString(length int) string {
	bytes := make([]byte, length/2)
	rand.Read(bytes)
	return fmt.Sprintf("%x", bytes)
}

// base64URLEncode encodes bytes to base64url without padding
func base64URLEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

// base64URLDecode decodes base64url (with or without padding)
func base64URLDecode(s string) ([]byte, error) {
	// Add padding if needed
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// generateScopedKeysJWE creates a JWE containing scoped keys encrypted with the client's public key
func generateScopedKeysJWE(keysJWKBase64 string) (string, error) {
	if keysJWKBase64 == "" {
		return "", fmt.Errorf("no keys_jwk provided")
	}

	// Decode the client's public key (JWK)
	jwkBytes, err := base64URLDecode(keysJWKBase64)
	if err != nil {
		return "", fmt.Errorf("failed to decode keys_jwk: %w", err)
	}

	var clientJWK struct {
		Crv string `json:"crv"`
		Kty string `json:"kty"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}
	if err := json.Unmarshal(jwkBytes, &clientJWK); err != nil {
		return "", fmt.Errorf("failed to parse keys_jwk: %w", err)
	}

	if clientJWK.Kty != "EC" || clientJWK.Crv != "P-256" {
		return "", fmt.Errorf("unsupported key type: %s/%s", clientJWK.Kty, clientJWK.Crv)
	}

	// Decode X and Y coordinates
	xBytes, err := base64URLDecode(clientJWK.X)
	if err != nil {
		return "", fmt.Errorf("failed to decode X: %w", err)
	}
	yBytes, err := base64URLDecode(clientJWK.Y)
	if err != nil {
		return "", fmt.Errorf("failed to decode Y: %w", err)
	}

	// Build the client's public key
	clientPubKeyBytes := make([]byte, 65)
	clientPubKeyBytes[0] = 0x04 // Uncompressed point
	copy(clientPubKeyBytes[1:33], xBytes)
	copy(clientPubKeyBytes[33:65], yBytes)

	clientPubKey, err := ecdh.P256().NewPublicKey(clientPubKeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to create client public key: %w", err)
	}

	// Generate ephemeral key pair for ECDH
	ephemeralPrivKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to generate ephemeral key: %w", err)
	}
	ephemeralPubKey := ephemeralPrivKey.PublicKey()

	// Perform ECDH to get shared secret
	sharedSecret, err := ephemeralPrivKey.ECDH(clientPubKey)
	if err != nil {
		return "", fmt.Errorf("ECDH failed: %w", err)
	}

	// Derive encryption key using Concat KDF (simplified HKDF for JWE ECDH-ES)
	// For ECDH-ES+A256GCM, we need a 256-bit key
	algID := []byte{0, 0, 0, 7, 'A', '2', '5', '6', 'G', 'C', 'M'}
	apu := []byte{}                  // No PartyUInfo
	apv := []byte{}                  // No PartyVInfo
	keyDataLen := []byte{0, 0, 1, 0} // 256 bits

	// Concat KDF: SHA-256(counter || Z || AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo)
	kdfInput := make([]byte, 0, 4+len(sharedSecret)+len(algID)+4+len(apu)+4+len(apv)+len(keyDataLen))
	kdfInput = append(kdfInput, 0, 0, 0, 1) // counter = 1
	kdfInput = append(kdfInput, sharedSecret...)
	kdfInput = append(kdfInput, algID...)
	kdfInput = append(kdfInput, 0, 0, 0, 0) // apu length = 0
	kdfInput = append(kdfInput, apu...)
	kdfInput = append(kdfInput, 0, 0, 0, 0) // apv length = 0
	kdfInput = append(kdfInput, apv...)
	kdfInput = append(kdfInput, keyDataLen...)

	derivedKeyHash := sha256.Sum256(kdfInput)
	derivedKey := derivedKeyHash[:32]

	// Generate random sync key for the scoped keys
	// Must be 64 bytes: first 32 for encryption, last 32 for HMAC
	syncKey := make([]byte, 64)
	rand.Read(syncKey)

	// Generate key fingerprint (random bytes, base64url encoded)
	fingerprint := make([]byte, 16)
	rand.Read(fingerprint)

	// kid format: "timestamp-fingerprint" where timestamp is milliseconds
	syncKid := fmt.Sprintf("%d-%s", time.Now().UnixMilli(), base64URLEncode(fingerprint))

	// Create scoped keys payload - each key needs "scope" field matching the key name
	scopedKeys := map[string]any{
		"https://identity.mozilla.com/apps/oldsync": map[string]any{
			"scope": "https://identity.mozilla.com/apps/oldsync",
			"kty":   "oct",
			"kid":   syncKid,
			"k":     base64URLEncode(syncKey),
		},
	}
	plaintext, _ := json.Marshal(scopedKeys)

	// Build JWE header first (needed for additionalData)
	ephPubBytes := ephemeralPubKey.Bytes()
	ephX := base64URLEncode(ephPubBytes[1:33])
	ephY := base64URLEncode(ephPubBytes[33:65])

	header := map[string]any{
		"alg": "ECDH-ES",
		"enc": "A256GCM",
		"epk": map[string]string{
			"kty": "EC",
			"crv": "P-256",
			"x":   ephX,
			"y":   ephY,
		},
	}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64URLEncode(headerJSON)

	// Encrypt with AES-256-GCM
	// additionalData is the base64url-encoded header (as bytes)
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	iv := make([]byte, 12)
	rand.Read(iv)

	// additionalData must be the UTF-8 bytes of the base64url-encoded header
	additionalData := []byte(headerB64)
	ciphertext := aesGCM.Seal(nil, iv, plaintext, additionalData)

	// Split ciphertext and tag (GCM tag is appended at the end)
	tagSize := aesGCM.Overhead()
	encryptedContent := ciphertext[:len(ciphertext)-tagSize]
	authTag := ciphertext[len(ciphertext)-tagSize:]

	// Construct JWE: header.encryptedKey.iv.ciphertext.tag
	// For ECDH-ES (direct key agreement), encrypted key is empty
	jwe := fmt.Sprintf("%s..%s.%s.%s",
		headerB64,
		base64URLEncode(iv),
		base64URLEncode(encryptedContent),
		base64URLEncode(authTag),
	)

	return jwe, nil
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
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #e4e4e4;
        }
        .container {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 16px;
            padding: 40px;
            width: 100%;
            max-width: 400px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
        }
        h1 {
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 8px;
            text-align: center;
        }
        .subtitle {
            color: #a0a0a0;
            text-align: center;
            margin-bottom: 32px;
            font-size: 14px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            font-size: 14px;
            font-weight: 500;
            color: #c0c0c0;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 14px 16px;
            border: 1px solid rgba(255, 255, 255, 0.15);
            border-radius: 8px;
            background: rgba(0, 0, 0, 0.3);
            color: #fff;
            font-size: 16px;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        input:focus {
            outline: none;
            border-color: #e94560;
            box-shadow: 0 0 0 3px rgba(233, 69, 96, 0.2);
        }
        button {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #e94560, #c23a51);
            border: none;
            border-radius: 8px;
            color: white;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.1s, box-shadow 0.2s;
        }
        button:hover {
            transform: translateY(-1px);
            box-shadow: 0 10px 20px rgba(233, 69, 96, 0.3);
        }
        button:active { transform: translateY(0); }
        .firefox-logo {
            width: 64px;
            height: 64px;
            margin: 0 auto 24px;
            display: block;
        }
    </style>
</head>
<body>
    <div class="container">
        <svg class="firefox-logo" viewBox="0 0 512 512">
            <defs>
                <radialGradient id="ff-a" cx="102.7" cy="87.1" r="363.3" gradientTransform="matrix(.9 0 0 .9 52.9 30.5)" gradientUnits="userSpaceOnUse">
                    <stop offset="0" stop-color="#ffbd4f"/>
                    <stop offset=".5" stop-color="#ff980e"/>
                    <stop offset="1" stop-color="#ff5634"/>
                </radialGradient>
            </defs>
            <circle cx="256" cy="256" r="220" fill="url(#ff-a)"/>
            <path fill="#fff" fill-opacity=".2" d="M256 76c99.4 0 180 80.6 180 180s-80.6 180-180 180S76 355.4 76 256 156.6 76 256 76m0-40C136.5 36 36 136.5 36 256s100.5 220 220 220 220-100.5 220-220S375.5 36 256 36z"/>
        </svg>
        <h1>Sign in</h1>
        <p class="subtitle">Continue to Firefox Sync</p>
        <form method="POST" action="/">
            <input type="hidden" name="client_id" value="{{.ClientID}}">
            <input type="hidden" name="state" value="{{.State}}">
            <input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
            <input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">
            <input type="hidden" name="keys_jwk" value="{{.KeysJWK}}">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required autofocus>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Sign in</button>
        </form>
    </div>
<script>
// WebChannel helper function
function sendWebChannel(command, data, messageId) {
    if (!messageId) {
        messageId = Date.now().toString(36) + '-' + Math.random().toString(36).substr(2);
    }
    const detail = {
        id: 'account_updates',
        message: {
            command: command,
            messageId: messageId,
            data: data
        }
    };
    console.log('[FxA] Sending:', command, detail);
    window.dispatchEvent(new CustomEvent('WebChannelMessageToChrome', {
        detail: JSON.stringify(detail)
    }));
}

// Listen for incoming WebChannel messages from Firefox
window.addEventListener('WebChannelMessageToContent', function(e) {
    console.log('[FxA] Received WebChannel message from Firefox:', e.detail);
    
    // Handle both string and object detail
    let detail = e.detail;
    if (typeof detail === 'string') {
        try {
            detail = JSON.parse(detail);
        } catch (err) {
            console.error('[FxA] Error parsing detail:', err);
            return;
        }
    }
    
    const command = detail.message?.command;
    const messageId = detail.message?.messageId;
    
    console.log('[FxA] Command:', command, 'MessageId:', messageId);
    
    if (command === 'fxaccounts:fxa_status') {
        console.log('[FxA] Responding to fxa_status request');
        sendWebChannel('fxaccounts:fxa_status', {
            signedInUser: null,
            capabilities: {
                choose_what_to_sync: true,
                engines: ['bookmarks', 'history', 'passwords', 'tabs', 'addons', 'preferences']
            }
        }, messageId);
    } else if (command === 'fxaccounts:can_link_account') {
        console.log('[FxA] Responding to can_link_account request');
        sendWebChannel('fxaccounts:can_link_account', {
            ok: true
        }, messageId);
    } else if (command === 'fxaccounts:login' || command === 'fxaccounts:oauth_login') {
        // Firefox is acknowledging our login - just log it
        console.log('[FxA] Firefox acknowledged:', command);
    } else {
        console.log('[FxA] Unhandled command:', command);
    }
});

// WebChannel is ready - Firefox will send fxaccounts:fxa_status when it's ready
console.log('[FxA] WebChannel listener ready');
</script>
</body>
</html>`
