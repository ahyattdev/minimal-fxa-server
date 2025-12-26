# minimal-fxa-server

A minimal Firefox Accounts server implementation in Go.

## Setup

1. Set these Firefox preferences in `about:config`:
   - `identity.fxaccounts.autoconfig.uri` = `http://localhost:8080/`
   - `identity.fxaccounts.allowHttp` = `true`

2. Restart Firefox

3. Run the server:
   ```bash
   HTTP_PORT=8080 go run main.go
   ```

4. Click "Sign in" in Firefox

## Environment Variables

- `HTTP_PORT` - Server port (default: `80`)
- `BASE_URL` - Base URL for the server (default: `http://localhost:$HTTP_PORT`)

## Default Credentials

- Username: `username`
- Password: `password`

## Current Status

### ✅ Working
- Firefox Accounts autoconfig (`.well-known/fxa-client-configuration`)
- WebChannel communication with Firefox
- Basic username/password authentication
- OAuth authorization flow with PKCE
- JWE key exchange (ECDH-ES + A256GCM)
- Scoped keys for sync (`https://identity.mozilla.com/apps/oldsync`)
- Token Server (`/token/1.0/sync/1.5`)
- Profile endpoint
- Device registration
- Session management

### 🔧 In Progress: Firefox Sync

The JWE key exchange and Token Server are now implemented. Firefox can receive encrypted sync keys
and obtain tokens for the Sync storage server.

**Note:** Full Sync functionality requires a Sync Storage Server implementation.
The Token Server points to `/storage/1.5/{uid}` but this endpoint is not yet implemented.

## API Endpoints

### Autoconfig
- `GET /.well-known/fxa-client-configuration`

### OAuth
- `GET /` - Login page
- `POST /` - Login submission
- `POST /oauth/v1/token` - Token exchange
- `POST /auth/v1/oauth/token` - Auth server token endpoint

### Profile
- `GET /profile/v1/profile` - User profile

### Account
- `POST /auth/v1/account/device` - Device registration
- `GET /auth/v1/recovery_email/status` - Email verification status
- `POST /auth/v1/account/keys` - Account keys (placeholder)
- `POST /auth/v1/session/destroy` - Session logout
- `POST /auth/v1/oauth/destroy` - OAuth token revocation

### Token Server (Sync)
- `GET /token/1.0/sync/1.5` - Get Sync storage token

# Attribution

_Firefox is a trademark of the Mozilla Foundation in the U.S. and other countries._
