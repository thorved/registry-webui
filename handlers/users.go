package handlers

import (
	"aithen/auth"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

// UsersPage displays the user management page
func (h *Handler) UsersPage(c *gin.Context) {
	session := sessions.Default(c)
	username := session.Get(auth.SessionUserKey)

	// Get all users with their roles directly from UserStore
	usersWithDetails := h.UserStore.ListUsersWithDetails()
	type userInfo struct {
		Username string
		Role     string
	}
	var infos []userInfo
	for _, u := range usersWithDetails {
		infos = append(infos, userInfo{
			Username: u.Username,
			Role:     u.Role,
		})
	}

	// Determine current user's role for template (used to show/hide actions)
	currentRole := "readonly"
	if username != nil {
		currentRole = h.UserStore.GetUserRole(username.(string))
	}

	c.HTML(http.StatusOK, "users.html", gin.H{
		"title":       "User Management",
		"username":    username,
		"users":       infos,
		"currentRole": currentRole,
	})
}

// ListUsers returns all users as JSON
func (h *Handler) ListUsers(c *gin.Context) {
	users := h.UserStore.ListUsers()
	c.JSON(http.StatusOK, gin.H{
		"users": users,
	})
}

// AddUser adds a new user
func (h *Handler) AddUser(c *gin.Context) {
	var req struct {
		Username          string `json:"username" binding:"required"`
		Password          string `json:"password" binding:"required"`
		FullName          string `json:"full_name"`
		Email             string `json:"email"`
		Role              string `json:"role"`
		Description       string `json:"description"`
		CustomPermissions *struct {
			Actions      []string `json:"actions"`
			Repositories []string `json:"repositories"`
		} `json:"custom_permissions"`
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

	// Only allow creating users if current session user is admin
	session := sessions.Default(c)
	current := session.Get(auth.SessionUserKey)
	if current == nil || (h.TokenService == nil || !h.TokenService.IsAdmin(current.(string))) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Only admin users can create new users"})
		return
	}

	// Add user to user store with role
	if err := h.UserStore.AddUser(req.Username, req.Password, req.Role, req.Email, req.FullName); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Note: No need to update ACL anymore - it's role-based
	c.JSON(http.StatusOK, gin.H{
		"message": "User created successfully with role: " + req.Role,
	})
}

// UpdatePassword updates a user's password
func (h *Handler) UpdatePassword(c *gin.Context) {
	username := c.Param("username")

	// Get current session user
	session := sessions.Default(c)
	currentUser := session.Get(auth.SessionUserKey)

	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Not authenticated",
		})
		return
	}

	currentUsername := currentUser.(string)

	// Check if user is trying to change their own password or is an admin
	isAdmin := h.TokenService != nil && h.TokenService.IsAdmin(currentUsername)
	isSelf := currentUsername == username

	if !isSelf && !isAdmin {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "You can only change your own password. Admin privileges required to change other users' passwords.",
		})
		return
	}

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

	if err := h.UserStore.UpdatePassword(username, req.Password); err != nil {
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

	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Not authenticated",
		})
		return
	}

	currentUsername := currentUser.(string)

	// Only admins can delete users
	if h.TokenService == nil || !h.TokenService.IsAdmin(currentUsername) {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Admin privileges required to delete users",
		})
		return
	}

	// Prevent deleting yourself
	if username == currentUsername {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Cannot delete your own account",
		})
		return
	}

	if err := h.UserStore.DeleteUser(username); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User deleted successfully",
	})
}
