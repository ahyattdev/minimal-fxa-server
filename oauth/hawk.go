package oauth

import (
	"crypto/sha256"
	"encoding/hex"
	"io"

	"golang.org/x/crypto/hkdf"
)

// FxA uses HKDF to derive Hawk credentials from the sessionToken
// See: https://github.com/mozilla/fxa/blob/main/packages/fxa-auth-server/lib/tokens/session_token.js

const (
	// FxA HKDF info string for session token derivation
	sessionTokenInfo = "identity.mozilla.com/picl/v1/sessionToken"
)

// DeriveHawkCredentials derives tokenId and reqHMACkey from a sessionToken
// using HKDF-SHA256 as specified by FxA protocol
func DeriveHawkCredentials(sessionToken []byte) (tokenID string, hawkKey []byte, err error) {
	// HKDF with SHA-256, empty salt, FxA-specific info string
	// Output: 64 bytes (32 for tokenId, 32 for reqHMACkey)
	hkdfReader := hkdf.New(sha256.New, sessionToken, nil, []byte(sessionTokenInfo))

	output := make([]byte, 64)
	if _, err := io.ReadFull(hkdfReader, output); err != nil {
		return "", nil, err
	}

	// First 32 bytes = tokenId, last 32 bytes = reqHMACkey
	tokenID = hex.EncodeToString(output[:32])
	hawkKey = output[32:64]

	return tokenID, hawkKey, nil
}

// DeriveHawkCredentialsFromHex derives Hawk credentials from a hex-encoded sessionToken
func DeriveHawkCredentialsFromHex(sessionTokenHex string) (tokenID string, hawkKey []byte, err error) {
	sessionToken, err := hex.DecodeString(sessionTokenHex)
	if err != nil {
		return "", nil, err
	}
	return DeriveHawkCredentials(sessionToken)
}
