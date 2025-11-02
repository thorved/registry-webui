package handlers

import (
	"encoding/base64"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// TokenResponse represents the Docker Registry token response
type TokenResponse struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// RegistryAuth handles the Docker Registry authentication endpoint
func (h *Handler) RegistryAuth(c *gin.Context) {
	// Get query parameters
	service := c.Query("service")
	scope := c.Query("scope")

	// Get scopes (can have multiple)
	scopes := c.QueryArray("scope")
	if len(scopes) == 0 && scope != "" {
		scopes = []string{scope}
	}

	// Get username and password from Basic Auth
	username, password := h.getBasicAuth(c)

	// If no credentials provided, return empty token for anonymous access
	if username == "" {
		token, err := h.TokenService.GenerateToken("", service, scopes)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to generate token",
			})
			return
		}

		c.JSON(http.StatusOK, TokenResponse{
			Token:       token,
			AccessToken: token,
			ExpiresIn:   900, // 15 minutes
		})
		return
	}

	// Authenticate the user
	if !h.UserStore.Authenticate(username, password) {
		log.Printf("[TOKEN] Authentication failed for user: %s", username)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid credentials",
		})
		return
	}

	// Generate token with user's permissions
	token, err := h.TokenService.GenerateToken(username, service, scopes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate token",
		})
		return
	}

	c.JSON(http.StatusOK, TokenResponse{
		Token:       token,
		AccessToken: token,
		ExpiresIn:   900, // 15 minutes
	})
}

// getBasicAuth extracts username and password from Authorization header
func (h *Handler) getBasicAuth(c *gin.Context) (string, string) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return "", ""
	}

	// Check if it's Basic auth
	if !strings.HasPrefix(authHeader, "Basic ") {
		return "", ""
	}

	// Decode base64
	payload := strings.TrimPrefix(authHeader, "Basic ")
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", ""
	}

	// Split username:password
	credentials := string(decoded)
	parts := strings.SplitN(credentials, ":", 2)
	if len(parts) != 2 {
		return "", ""
	}

	return parts[0], parts[1]
}

// GetPublicKey returns the public key for token verification
func (h *Handler) GetPublicKey(c *gin.Context) {
	publicKey, err := h.TokenService.GetPublicKey()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get public key",
		})
		return
	}

	c.String(http.StatusOK, publicKey)
}
