package handlers

import (
	"net/http"
	"registry-webui/auth"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

// UsersPage displays the user management page
func (h *Handler) UsersPage(c *gin.Context) {
	session := sessions.Default(c)
	username := session.Get(auth.SessionUserKey)
	users := h.Auth.ListUsers()

	c.HTML(http.StatusOK, "users.html", gin.H{
		"title":    "User Management",
		"username": username,
		"users":    users,
	})
}

// ListUsers returns all users as JSON
func (h *Handler) ListUsers(c *gin.Context) {
	users := h.Auth.ListUsers()
	c.JSON(http.StatusOK, gin.H{
		"users": users,
	})
}

// AddUser adds a new user
func (h *Handler) AddUser(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Username and password are required",
		})
		return
	}

	// Validate username
	if len(req.Username) < 3 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Username must be at least 3 characters",
		})
		return
	}

	// Validate password
	if len(req.Password) < 6 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Password must be at least 6 characters",
		})
		return
	}

	if err := h.Auth.AddUser(req.Username, req.Password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User added successfully",
	})
}

// UpdatePassword updates a user's password
func (h *Handler) UpdatePassword(c *gin.Context) {
	username := c.Param("username")

	var req struct {
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Password is required",
		})
		return
	}

	// Validate password
	if len(req.Password) < 6 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Password must be at least 6 characters",
		})
		return
	}

	if err := h.Auth.UpdatePassword(username, req.Password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Password updated successfully",
	})
}

// DeleteUser deletes a user
func (h *Handler) DeleteUser(c *gin.Context) {
	username := c.Param("username")
	session := sessions.Default(c)
	currentUser := session.Get(auth.SessionUserKey)

	// Prevent deleting yourself
	if username == currentUser {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Cannot delete your own account",
		})
		return
	}

	if err := h.Auth.DeleteUser(username); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User deleted successfully",
	})
}
