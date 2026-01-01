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

### Required
- `DATABASE_URI` - PostgreSQL connection string
- `JWT_PRIVATE_KEY` - RSA private key in PEM format for signing JWTs

### Optional
- `HTTP_PORT` - Server port (default: `80`)
- `BASE_URL` - Base URL for the server (default: `http://localhost:$HTTP_PORT`)
- `SYNC_SERVER_URL` - URL to syncstorage-rs token server
- `AUTH_METHOD` - Authentication method: `local` or `oidc` (default: `local`)
- `FXA_SOCKET` - Unix socket path for user management gRPC (default: `/tmp/fxa-usermgmt.sock`)

### VAPID (Push Notifications)
- `VAPID_PRIVATE_KEY` - Base64url-encoded EC P-256 private key
- `VAPID_PUBLIC_KEY` - Base64url-encoded EC P-256 public key
- `VAPID_EMAIL` - Contact email for push service (default: `mailto:admin@localhost`)

### OIDC Authentication (when AUTH_METHOD=oidc)
- `OIDC_ISSUER` - OIDC provider URL (required)
- `OIDC_CLIENT_ID` - OAuth client ID (required)
- `OIDC_CLIENT_SECRET` - OAuth client secret
- `OIDC_REDIRECT_URL` - Callback URL (default: `{BASE_URL}/oidc/callback`)
- `OIDC_SCOPES` - Comma-separated scopes (default: `openid,email,profile`)

## Authentication

### Local Authentication (default)

Users are stored in the PostgreSQL database with bcrypt-hashed passwords. There are no default credentials - users must be created using the CLI.

#### User Management CLI

```bash
# Create a user (prompts for password)
fxa-user create user@example.com

# Delete a user
fxa-user delete user@example.com

# Change password
fxa-user passwd user@example.com

# List all users
fxa-user list
```

The CLI connects via Unix socket for security. In Docker/Kubernetes:
```bash
kubectl exec -it <pod> -- fxa-user create admin@example.com
```

### OIDC Authentication

Set `AUTH_METHOD=oidc` and configure the OIDC environment variables. Users will be redirected to your identity provider for authentication.

## API Endpoints

### Autoconfig
- `GET /.well-known/fxa-client-configuration`

### OAuth
- `GET /` - Login page
- `POST /` - Login submission
- `POST /oauth/v1/token` - Token exchange
- `POST /oauth/v1/verify` - Token verification
- `GET /oauth/v1/jwks` - JSON Web Key Set

### Auth Server
- `POST /auth/v1/oauth/token` - Auth server token endpoint
- `POST /auth/v1/account/device` - Device registration
- `GET /auth/v1/account/devices` - List devices
- `POST /auth/v1/account/devices/notify` - Push notifications
- `GET /auth/v1/account/device/commands` - Device commands
- `GET /auth/v1/account/attached_clients` - Attached clients
- `GET /auth/v1/recovery_email/status` - Email verification status
- `POST /auth/v1/account/keys` - Account keys
- `POST /auth/v1/session/destroy` - Session logout
- `POST /auth/v1/oauth/destroy` - OAuth token revocation

### Profile
- `GET /profile/v1/profile` - User profile

## Building

```bash
# Build both binaries
make build

# Regenerate gRPC code (requires protoc)
make generate
```

## Docker

```bash
docker build -t minimal-fxa-server .
docker run -e DATABASE_URI=... -e JWT_PRIVATE_KEY=... minimal-fxa-server
```

# Attribution

_Firefox is a trademark of the Mozilla Foundation in the U.S. and other countries._
