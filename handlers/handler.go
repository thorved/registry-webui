package handlers

import (
	"registry-webui/auth"
	"registry-webui/config"
	"registry-webui/registry"
)

// Handler contains all dependencies for HTTP handlers
type Handler struct {
	Config       *config.Config
	UserStore    *auth.UserStore
	Registry     *registry.Client
	TokenService *auth.TokenService
	TokenStore   *auth.PersonalTokenStore
}

// NewHandler creates a new handler instance
func NewHandler(cfg *config.Config, userStore *auth.UserStore, registryClient *registry.Client, tokenService *auth.TokenService, tokenStore *auth.PersonalTokenStore) *Handler {
	return &Handler{
		Config:       cfg,
		UserStore:    userStore,
		Registry:     registryClient,
		TokenService: tokenService,
		TokenStore:   tokenStore,
	}
}
