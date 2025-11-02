package auth

import (
	"net/http"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

const (
	SessionUserKey = "username"
	SessionTimeout = 24 * time.Hour
)

// LoginRequired is a middleware that checks if user is authenticated
func LoginRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		username := session.Get(SessionUserKey)

		if username == nil {
			// Check if it's an AJAX request (HTMX)
			if c.GetHeader("HX-Request") == "true" {
				c.Header("HX-Redirect", "/login")
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}

		c.Set("username", username)
		c.Next()
	}
}

// GetCurrentUser returns the current logged-in username
func GetCurrentUser(c *gin.Context) string {
	if username, exists := c.Get("username"); exists {
		return username.(string)
	}
	return ""
}
