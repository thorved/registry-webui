package main

import (
	"fmt"
	"html/template"
	"log"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"

	"registry-webui/auth"
	"registry-webui/config"
	"registry-webui/handlers"
	"registry-webui/registry"
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
	}
	r.SetFuncMap(funcMap)
	r.LoadHTMLGlob("templates/*.html")

	// Initialize handlers
	h := handlers.NewHandler(cfg, userStore, registryClient, tokenService, tokenStore)

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

			// Garbage collection
			api.POST("/gc", h.RunGarbageCollection)
		}
	}

	// Start server
	port := cfg.WebUIPort
	log.Printf("Starting Registry Web UI on port %s", port)
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
