# GitHub Copilot Instructions for Aithen Project

## Project Overview
Aithen is a Docker Registry Web UI with authentication and token-based access control, built with Go and deployed using Docker.

## Tech Stack

### Backend
- **Language**: Go 1.23+
- **Web Framework**: Gin (github.com/gin-gonic/gin)
- **Session Management**: gin-contrib/sessions with cookie store
- **Authentication**: 
  - Username/password (bcrypt hashing)
  - WebAuthn/Passkeys (go-webauthn/webauthn)
  - Personal Access Tokens (PAT)
  - JWT-based token service

### Frontend
- **Templating**: Go HTML templates
- **Interactivity**: HTMX
- **Styling**: Tailwind CSS (via CDN)

### Infrastructure
- **Container Runtime**: Docker & Docker Compose
- **Registry**: Docker Registry v3 (registry:3 image)
- **Base Image**: golang:1.23-alpine (build), alpine:latest (runtime)
- **Data Storage**: File-based JSON stores for users, tokens, ACLs

## Project Structure
```
/
├── auth/           # Authentication & authorization logic
├── config/         # Configuration management
├── handlers/       # HTTP request handlers
├── registry/       # Docker Registry API client
├── templates/      # HTML templates
├── data/           # Persistent data (mounted volumes)
│   ├── auth/      # User data, tokens, ACLs
│   ├── certs/     # JWT certificates, JWKS
│   └── registry/  # Registry blob storage
└── main.go        # Application entry point
```

## Key Components

### Authentication Flow
1. Users authenticate via password, passkey, or personal access token
2. Session tokens are generated for authenticated users
3. Registry requests use these tokens to obtain JWT tokens from `/auth` endpoint
4. ACL rules control repository access based on user roles

### Docker Registry Integration
- Registry configured with token-based auth pointing to Aithen
- Auth realm: `http://localhost:8080/auth` (or custom domain)
- JWKS endpoint at `/auth/jwks` for token verification
- Supports pull, push, and delete operations with permission checks

### API Endpoints
- `/auth` - Registry token authentication
- `/api/repositories` - List repositories
- `/api/repository/:repo` - Repository details
- `/api/tokens` - Manage personal access tokens
- `/api/users` - User management
- `/api/gc` - Garbage collection

## Coding Guidelines

### Go Conventions
- Use struct-based handlers with dependency injection
- Implement middleware for authentication checks
- Store configuration in environment variables
- Use sync.RWMutex for thread-safe in-memory stores
- Log actions with `[DEBUG]`, `[ERROR]`, `[TOKEN]` prefixes

### Error Handling
- Return descriptive error messages to users
- Log detailed errors for debugging
- Use proper HTTP status codes
- Handle registry 404 errors gracefully (corrupted data scenarios)

### Security
- Never store passwords in plain text (use bcrypt)
- Generate secure random tokens (crypto/rand)
- Validate token permissions before operations
- Check ACL rules for repository access
- Regenerate session tokens when invalid

## Docker Configuration
- **Registry Storage**: `/var/lib/registry` inside container
- **Config Path**: `/etc/distribution/config.yml`
- **Network**: Bridge network for container communication
- **Volumes**: Persist auth data, certs, and registry blobs

## Common Patterns
- Session management via `gin-contrib/sessions`
- Registry client with token caching and scope-based auth
- HTML responses for browser requests, JSON for API calls
- HTMX partial page updates for interactive UI

## Important Notes
- Personal access tokens start with `pat_` prefix
- Session tokens are in-memory only (lost on restart)
- Registry manifest digests must match Accept headers
- Garbage collection cleans both corrupted tags and unused blobs
- WebAuthn requires HTTPS in production (RP ID must match domain)
