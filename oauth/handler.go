package oauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Handler struct {
	baseURL       string
	username      string
	password      string
	authCodes     map[string]*AuthCode
	authCodesMu   sync.RWMutex
	loginTemplate *template.Template
}

type AuthCode struct {
	Code                string
	ClientID            string
	CodeChallenge       string
	CodeChallengeMethod string
	State               string
	KeysJWK             string
	CreatedAt           time.Time
}

func NewHandler(baseURL, username, password string) *Handler {
	return &Handler{
		baseURL:       baseURL,
		username:      username,
		password:      password,
		authCodes:     make(map[string]*AuthCode),
		loginTemplate: template.Must(template.New("login").Parse(loginHTML)),
	}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", h.handleAuthorizePage)
	mux.HandleFunc("POST /{$}", h.handleLogin)
	mux.HandleFunc("POST /oauth/v1/token", h.handleToken)

	// Auth server endpoints
	mux.HandleFunc("POST /auth/v1/oauth/token", h.handleAuthToken)
	mux.HandleFunc("POST /auth/v1/account/device", h.handleDevice)
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

	slog.Info("User authenticated, generated auth code", "username", username)

	// Store the auth code for token exchange
	h.authCodesMu.Lock()
	h.authCodes[code] = &AuthCode{
		Code:                code,
		ClientID:            r.FormValue("client_id"),
		CodeChallenge:       r.FormValue("code_challenge"),
		CodeChallengeMethod: r.FormValue("code_challenge_method"),
		State:               state,
		KeysJWK:             r.FormValue("keys_jwk"),
		CreatedAt:           time.Now(),
	}
	h.authCodesMu.Unlock()

	// Generate consistent UID and session token
	uid := fmt.Sprintf("%x", sha256.Sum256([]byte(h.username)))[:32]
	sessionToken := generateHexString(64)

	// Prepare login data (for fxaccounts:login)
	loginData := map[string]any{
		"uid":          uid,
		"email":        h.username + "@localhost",
		"sessionToken": sessionToken,
		"verified":     true,
		"services": map[string]any{
			"sync": map[string]string{},
		},
	}
	loginJSON, _ := json.Marshal(loginData)

	// Prepare OAuth data (for fxaccounts:oauth_login)
	oauthData := map[string]any{
		"code":  code,
		"state": state,
	}
	oauthJSON, _ := json.Marshal(oauthData)

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
  
  // Listen for responses from Firefox
  window.addEventListener('WebChannelMessageToContent', function(e) {
    console.log('[FxA] Received from Firefox:', e.detail);
    let detail = e.detail;
    if (typeof detail === 'string') {
      try { detail = JSON.parse(detail); } catch(err) { return; }
    }
    const cmd = detail.message?.command;
    const msgId = detail.message?.messageId;
    
    if (cmd === 'fxaccounts:can_link_account') {
      sendWebChannel('fxaccounts:can_link_account', { ok: true }, msgId);
    }
  });
  
  status.textContent = 'Setting up account...';
  
  // Step 1: Send fxaccounts:login to set up the account
  sendWebChannel('fxaccounts:login', loginData);
  console.log('[FxA] Login sent with data:', loginData);
  
  // Step 2: Send fxaccounts:oauth_login to complete OAuth flow
  setTimeout(function() {
    status.textContent = 'Completing OAuth flow...';
    sendWebChannel('fxaccounts:oauth_login', oauthData);
    console.log('[FxA] OAuth login sent with data:', oauthData);
    status.textContent = 'Sign-in complete! You can close this tab.';
  }, 500);
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

	h.authCodesMu.RLock()
	authCode, exists := h.authCodes[code]
	h.authCodesMu.RUnlock()

	if !exists {
		slog.Warn("Invalid auth code", "code", code)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		return
	}

	// Get KeysJWK before deleting
	keysJWK := authCode.KeysJWK

	// TODO: Verify code_verifier against code_challenge (PKCE)

	h.authCodesMu.Lock()
	delete(h.authCodes, code)
	h.authCodesMu.Unlock()

	accessToken := generateRandomString(64)
	refreshToken := generateRandomString(64)

	response := map[string]any{
		"access_token":  accessToken,
		"token_type":    "bearer",
		"expires_in":    3600,
		"refresh_token": refreshToken,
		"scope":         "https://identity.mozilla.com/apps/oldsync profile",
	}

	// Generate keys_jwe if keys_jwk was provided
	if keysJWK != "" {
		keysJWE, err := generateScopedKeysJWE(keysJWK)
		if err != nil {
			slog.Warn("Failed to generate keys_jwe", "error", err)
		} else {
			response["keys_jwe"] = keysJWE
			slog.Info("Generated keys_jwe for sync")
		}
	}

	slog.Info("Token issued", "client_id", authCode.ClientID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) handleAuthToken(w http.ResponseWriter, r *http.Request) {
	// Firefox sends JSON body for token requests
	var req struct {
		Code         string `json:"code"`
		ClientID     string `json:"client_id"`
		CodeVerifier string `json:"code_verifier"`
		GrantType    string `json:"grant_type"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Warn("Failed to decode token request", "error", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	slog.Info("Token exchange request", "grant_type", req.GrantType, "client_id", req.ClientID)

	if req.Code == "" {
		slog.Warn("Empty code in token request")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request"})
		return
	}

	h.authCodesMu.RLock()
	authCode, exists := h.authCodes[req.Code]
	h.authCodesMu.RUnlock()

	if !exists {
		slog.Warn("Invalid auth code in auth token endpoint")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		return
	}

	// Get KeysJWK before deleting
	keysJWK := authCode.KeysJWK

	h.authCodesMu.Lock()
	delete(h.authCodes, req.Code)
	h.authCodesMu.Unlock()

	accessToken := generateRandomString(64)
	refreshToken := generateRandomString(64)

	response := map[string]any{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "bearer",
		"expires_in":    3600,
		"scope":         "https://identity.mozilla.com/apps/oldsync profile",
	}

	// Generate keys_jwe if keys_jwk was provided
	if keysJWK != "" {
		keysJWE, err := generateScopedKeysJWE(keysJWK)
		if err != nil {
			slog.Warn("Failed to generate keys_jwe", "error", err)
		} else {
			response["keys_jwe"] = keysJWE
			slog.Info("Generated keys_jwe for sync")
		}
	}

	slog.Info("Token issued successfully")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) handleDevice(w http.ResponseWriter, r *http.Request) {
	slog.Info("Device registration request")

	deviceID := generateRandomString(32)

	response := map[string]any{
		"id":            deviceID,
		"name":          "Firefox",
		"type":          "desktop",
		"pushCallback":  nil,
		"pushPublicKey": nil,
		"pushAuthKey":   nil,
		"createdAt":     time.Now().UnixMilli(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
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
	syncKey := make([]byte, 32)
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

// Initialize WebChannel
sendWebChannel('fxaccounts:loaded');
console.log('[FxA] WebChannel initialized');
</script>
</body>
</html>`
