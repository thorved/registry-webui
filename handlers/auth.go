package handlers

import (
	"net/http"

	"registry-webui/auth"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

// ShowLoginPage renders the login page
func (h *Handler) ShowLoginPage(c *gin.Context) {
	session := sessions.Default(c)
	username := session.Get(auth.SessionUserKey)

	if username != nil {
		c.Redirect(http.StatusFound, "/")
		return
	}

	c.HTML(http.StatusOK, "login.html", gin.H{
		"title": "Login - Registry Web UI",
	})
}

// Login handles user authentication
func (h *Handler) Login(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	if username == "" || password == "" {
		c.HTML(http.StatusBadRequest, "login.html", gin.H{
			"title": "Login - Registry Web UI",
			"error": "Username and password are required",
		})
		return
	}

	// Authenticate against htpasswd
	if !h.Auth.Authenticate(username, password) {
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{
			"title": "Login - Registry Web UI",
			"error": "Invalid username or password",
		})
		return
	}

	// Create session and store credentials
	session := sessions.Default(c)
	session.Set(auth.SessionUserKey, username)
	session.Set("password", password) // Store password for registry API calls
	if err := session.Save(); err != nil {
		c.HTML(http.StatusInternalServerError, "login.html", gin.H{
			"title": "Login - Registry Web UI",
			"error": "Failed to create session",
		})
		return
	}

	// For HTMX requests, redirect via header
	if c.GetHeader("HX-Request") == "true" {
		c.Header("HX-Redirect", "/")
		c.Status(http.StatusOK)
		return
	}

	c.Redirect(http.StatusFound, "/")
}

// Logout handles user logout
func (h *Handler) Logout(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	session.Save()

	c.Redirect(http.StatusFound, "/login")
}
