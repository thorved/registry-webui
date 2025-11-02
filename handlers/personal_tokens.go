package handlers

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"aithen/auth"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

// ShowTokens displays the tokens management page
func (h *Handler) ShowTokens(c *gin.Context) {
	session := sessions.Default(c)
	username := session.Get(auth.SessionUserKey)

	if username == nil {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	c.HTML(http.StatusOK, "tokens.html", gin.H{
		"title":    "Access Tokens",
		"username": username,
	})
}

// ListTokens returns all tokens for the current user
func (h *Handler) ListTokens(c *gin.Context) {
	session := sessions.Default(c)
	username := session.Get(auth.SessionUserKey)

	if username == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	tokens := h.TokenStore.ListTokens(username.(string))

	c.HTML(http.StatusOK, "tokens_list.html", gin.H{
		"tokens": tokens,
	})
}

// CreatePersonalToken creates a new personal access token
func (h *Handler) CreatePersonalToken(c *gin.Context) {
	session := sessions.Default(c)
	username := session.Get(auth.SessionUserKey)

	if username == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	var req struct {
		Name         string   `json:"name" binding:"required"`
		Description  string   `json:"description"`
		Permissions  []string `json:"permissions" binding:"required"`
		Repositories []string `json:"repositories" binding:"required"`
		ExpiresIn    int      `json:"expires_in"` // Days, 0 = never expires
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate permissions
	validPerms := map[string]bool{"pull": true, "push": true, "delete": true}
	for _, perm := range req.Permissions {
		if !validPerms[perm] {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid permission: %s", perm)})
			return
		}
	}

	// Calculate expiration
	var expiresIn *time.Duration
	if req.ExpiresIn > 0 {
		duration := time.Duration(req.ExpiresIn) * 24 * time.Hour
		expiresIn = &duration
	}

	token, err := h.TokenStore.CreateToken(
		username.(string),
		req.Name,
		req.Description,
		req.Permissions,
		req.Repositories,
		expiresIn,
	)

	if err != nil {
		log.Printf("[ERROR] Failed to create token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"token":   token,
		"message": "Token created successfully. Copy it now, you won't see it again!",
	})
}

// DeletePersonalToken deletes a personal access token
func (h *Handler) DeletePersonalToken(c *gin.Context) {
	session := sessions.Default(c)
	username := session.Get(auth.SessionUserKey)

	if username == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	tokenID := c.Param("id")

	if err := h.TokenStore.DeleteToken(tokenID, username.(string)); err != nil {
		log.Printf("[ERROR] Failed to delete token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Token deleted successfully",
	})
}
