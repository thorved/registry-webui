package main

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"

	"aithen/auth"
	"aithen/config"
	"aithen/handlers"
	"aithen/registry"
)

func main() {
	// Load configuration
	cfg := config.Load()

	// Initialize user store (replaces htpasswd)
	userStore, err := auth.NewUserStore("/auth/users.json")
	if err != nil {
		log.Fatalf("Failed to initialize user store: %v", err)
	}
	log.Println("User store initialized successfully")

	// Initialize ACL with user store reference
	acl, err := auth.NewACL(cfg.ACLPath, userStore)
	if err != nil {
		log.Fatalf("Failed to initialize ACL: %v", err)
	}
	log.Printf("Loaded %d ACL entries", len(acl.Entries))

	// Initialize token service
	tokenExpiration := time.Duration(cfg.TokenExpiration) * time.Second
	tokenService, err := auth.NewTokenService(cfg.TokenKeyPath, cfg.TokenIssuer, tokenExpiration, acl)
	if err != nil {
		log.Fatalf("Failed to initialize token service: %v", err)
	}
	log.Println("Token service initialized successfully")

	// Initialize personal token store
	tokenStore, err := auth.NewPersonalTokenStore("/auth/personal_tokens.json")
	if err != nil {
		log.Fatalf("Failed to initialize token store: %v", err)
	}
	log.Println("Personal token store initialized successfully")

	// Initialize WebAuthn service
	webAuthnService, err := auth.NewWebAuthnService(
		cfg.WebAuthnRPName,
		cfg.WebAuthnRPID,
		cfg.WebAuthnOrigin,
	)
	if err != nil {
		log.Fatalf("Failed to initialize WebAuthn service: %v", err)
	}
	log.Println("WebAuthn service initialized successfully")

	// Initialize registry client
	registryClient := registry.NewClient(cfg.RegistryURL, cfg.RegistryUsername, cfg.RegistryPassword)

	// Check registry connectivity
	if err := registryClient.CheckHealth(); err != nil {
		log.Printf("Warning: Registry health check failed: %v", err)
	} else {
		log.Println("Successfully connected to registry")
	}

	// Initialize Gin
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	// Setup sessions
	store := cookie.NewStore([]byte(cfg.SessionSecret))
	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   86400, // 24 hours
		HttpOnly: true,
		Secure:   false, // Set to true if using HTTPS
	})
	r.Use(sessions.Sessions("registry-session", store))

	// Load HTML templates with custom functions
	funcMap := template.FuncMap{
		"formatSize": formatSize,
		"safeID":     safeID,
	}
	r.SetFuncMap(funcMap)
	r.LoadHTMLGlob("templates/*.html")

	// Initialize handlers
	h := handlers.NewHandler(cfg, userStore, registryClient, tokenService, tokenStore, webAuthnService)

	// Docker Registry token authentication endpoint (public)
	r.GET("/auth", h.RegistryAuth)
	r.GET("/token", h.RegistryAuth) // Some clients use /token
	r.GET("/auth/publickey", h.GetPublicKey)
	r.GET("/auth/jwks", h.JWKSHandler) // JWKS endpoint for registry
	r.GET("/jwks.json", h.JWKSHandler) // Alternative JWKS endpoint

	// Public routes
	r.GET("/login", h.ShowLoginPage)
	r.POST("/login", h.Login)
	r.GET("/logout", h.Logout)

	// Passkey authentication routes (public)
	r.GET("/auth/passkey/login/begin", h.BeginPasskeyLogin)
	r.POST("/auth/passkey/login/finish", h.FinishPasskeyLogin)
	// Discoverable/usernameless passkey login
	r.GET("/auth/passkey/login/discoverable/begin", h.BeginDiscoverablePasskeyLogin)
	r.POST("/auth/passkey/login/discoverable/finish", h.FinishDiscoverablePasskeyLogin)

	// Protected routes
	protected := r.Group("/")
	protected.Use(auth.LoginRequired())
	{
		// Dashboard
		protected.GET("/", h.ShowDashboard)

		// User Management
		protected.GET("/users", h.UsersPage)

		// Token Management
		protected.GET("/tokens", h.ShowTokens)

		// Passkey Management
		protected.GET("/passkeys", h.ShowPasskeysPage)

		// API routes
		api := protected.Group("/api")
		{
			api.GET("/repositories", h.ListRepositories)
			api.GET("/repository/:repo", h.ShowRepository)
			api.DELETE("/repository/:repo", h.DeleteRepository)
			api.GET("/repository/:repo/tag/:tag", h.ShowImageDetails)
			api.DELETE("/repository/:repo/tag/:tag", h.DeleteImage)

			// User management APIs
			api.GET("/users", h.ListUsers)
			api.POST("/users", h.AddUser)
			api.PUT("/users/:username/password", h.UpdatePassword)
			api.DELETE("/users/:username", h.DeleteUser)

			// Personal token APIs
			api.GET("/tokens", h.ListTokens)
			api.POST("/tokens", h.CreatePersonalToken)
			api.DELETE("/tokens/:id", h.DeletePersonalToken)

			// Passkey management APIs
			api.GET("/passkeys", h.ListPasskeys)
			api.POST("/passkeys/register/begin", h.BeginPasskeyRegistration)
			api.POST("/passkeys/register/finish", h.FinishPasskeyRegistration)
			api.DELETE("/passkeys/:id", h.DeletePasskey)
			api.PUT("/passkeys/:id/name", h.UpdatePasskeyName)

			// Garbage collection
			api.POST("/gc", h.RunGarbageCollection)
		}
	}

	// Start server
	port := cfg.WebUIPort
	log.Printf("Starting Aithen on port %s", port)
	log.Printf("Registry URL: %s", cfg.RegistryURL)
	log.Printf("Token authentication endpoint: http://localhost:%s/auth", port)

	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// formatSize formats bytes to human-readable size
func formatSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// safeID converts a string to a safe CSS ID using base64 encoding
func safeID(s string) string {
	// Use URL-safe base64 encoding to preserve the original name
	// while making it safe for use as CSS ID
	encoded := base64.RawURLEncoding.EncodeToString([]byte(s))
	return encoded
}
