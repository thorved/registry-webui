package handlers

import (
	"fmt"
	"log"
	"net/http"

	"registry-webui/auth"
	"registry-webui/registry"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

// getRegistryClient creates a registry client with user credentials from session
func (h *Handler) getRegistryClient(c *gin.Context) *registry.Client {
	session := sessions.Default(c)
	username := session.Get(auth.SessionUserKey)
	password := session.Get("password")

	// Log for debugging
	if username != nil {
		log.Printf("[DEBUG] Creating registry client for user: %s (has password: %v)\n", username, password != nil)
	} else {
		log.Println("[DEBUG] No username in session, creating anonymous client")
	}

	if username != nil && password != nil {
		return registry.NewClient(h.Config.RegistryURL, username.(string), password.(string))
	}

	// If no credentials in session, use empty credentials
	// The client will attempt to get tokens without authentication
	return registry.NewClient(h.Config.RegistryURL, "", "")
}

// ShowDashboard renders the main dashboard
func (h *Handler) ShowDashboard(c *gin.Context) {
	username := auth.GetCurrentUser(c)

	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"title":    "Dashboard - Registry Web UI",
		"username": username,
	})
}

// ListRepositories returns all repositories (filters out empty ones)
func (h *Handler) ListRepositories(c *gin.Context) {
	log.Println("[DEBUG] ListRepositories called")
	registryClient := h.getRegistryClient(c)
	log.Println("[DEBUG] Got registry client")
	repositories, err := registryClient.ListRepositories()
	log.Printf("[DEBUG] ListRepositories result: repos=%v, err=%v\n", repositories, err)
	if err != nil {
		log.Printf("[ERROR] Failed to fetch repositories: %v\n", err)
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": fmt.Sprintf("Failed to fetch repositories: %v", err),
		})
		return
	}

	// Filter out repositories with no tags
	filteredRepos := []string{}
	for _, repo := range repositories {
		tags, err := registryClient.ListTags(repo)
		if err != nil {
			// If error fetching tags, skip this repo
			log.Printf("[DEBUG] Skipping repo %s due to error: %v", repo, err)
			continue
		}
		log.Printf("[DEBUG] Repo %s has %d tags: %v", repo, len(tags), tags)
		// Only include repos that have at least one tag
		if len(tags) > 0 {
			filteredRepos = append(filteredRepos, repo)
		}
	}
	log.Printf("[DEBUG] Filtered repos count: %d, repos: %v", len(filteredRepos), filteredRepos)

	// Get user role for permission checks
	username, exists := c.Get("username")
	log.Printf("[DEBUG] Username from context: %v, exists: %v", username, exists)
	userRole := "readonly" // default
	if username != nil {
		usernameStr := username.(string)
		log.Printf("[DEBUG] Looking up user: %s", usernameStr)
		if user, err := h.UserStore.GetUser(usernameStr); err == nil {
			userRole = user.Role
			log.Printf("[DEBUG] User found: %s, Role: %s", usernameStr, userRole)
		} else {
			log.Printf("[DEBUG] User lookup failed: %v", err)
		}
	} else {
		log.Printf("[DEBUG] Username is nil, using default role: %s", userRole)
	}

	log.Printf("[DEBUG] Rendering repositories.html with userRole: %s", userRole)
	c.HTML(http.StatusOK, "repositories.html", gin.H{
		"repositories": filteredRepos,
		"userRole":     userRole,
	})
}

// ShowRepository displays details of a specific repository
func (h *Handler) ShowRepository(c *gin.Context) {
	repo := c.Param("repo")
	registryClient := h.getRegistryClient(c)

	tags, err := registryClient.ListTags(repo)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": fmt.Sprintf("Failed to fetch tags: %v", err),
		})
		return
	}

	// Get user role for permission checks
	username, exists := c.Get("username")
	log.Printf("[DEBUG] ShowRepository - Username from context: %v, exists: %v", username, exists)
	userRole := "readonly" // default
	if username != nil {
		usernameStr := username.(string)
		log.Printf("[DEBUG] ShowRepository - Looking up user: %s", usernameStr)
		if user, err := h.UserStore.GetUser(usernameStr); err == nil {
			userRole = user.Role
			log.Printf("[DEBUG] ShowRepository - User found: %s, Role: %s", usernameStr, userRole)
		} else {
			log.Printf("[DEBUG] ShowRepository - User lookup failed: %v", err)
		}
	} else {
		log.Printf("[DEBUG] ShowRepository - Username is nil, using default role: %s", userRole)
	}

	log.Printf("[DEBUG] Rendering repository_detail.html with userRole: %s", userRole)
	c.HTML(http.StatusOK, "repository_detail.html", gin.H{
		"repository": repo,
		"tags":       tags,
		"userRole":   userRole,
	})
}

// ShowImageDetails displays detailed information about an image
func (h *Handler) ShowImageDetails(c *gin.Context) {
	repo := c.Param("repo")
	tag := c.Param("tag")
	registryClient := h.getRegistryClient(c)

	imageInfo, err := registryClient.GetImageInfo(repo, tag)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": fmt.Sprintf("Failed to fetch image info: %v", err),
		})
		return
	}

	manifest, _, err := registryClient.GetManifest(repo, tag)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": fmt.Sprintf("Failed to fetch manifest: %v", err),
		})
		return
	}

	c.HTML(http.StatusOK, "image_detail.html", gin.H{
		"imageInfo": imageInfo,
		"manifest":  manifest,
	})
}

// DeleteImage handles image deletion
func (h *Handler) DeleteImage(c *gin.Context) {
	repo := c.Param("repo")
	tag := c.Param("tag")
	registryClient := h.getRegistryClient(c)

	// First get the digest for this tag
	_, digest, err := registryClient.GetManifest(repo, tag)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": fmt.Sprintf("Failed to fetch image digest: %v", err),
		})
		return
	}

	// Delete using the digest
	if err := registryClient.DeleteImage(repo, digest); err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": fmt.Sprintf("Failed to delete image: %v", err),
		})
		return
	}

	// Return success message for HTMX
	c.HTML(http.StatusOK, "delete_success.html", gin.H{
		"message": fmt.Sprintf("Successfully deleted %s:%s", repo, tag),
	})
}

// DeleteRepository handles deletion of an entire repository (all tags)
func (h *Handler) DeleteRepository(c *gin.Context) {
	repo := c.Param("repo")
	registryClient := h.getRegistryClient(c)

	// First, get all tags for this repository
	tags, err := registryClient.ListTags(repo)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("Failed to fetch tags: %v", err),
		})
		return
	}

	if len(tags) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"message": fmt.Sprintf("Repository '%s' has no tags to delete. It appears to already be empty.", repo),
		})
		return
	}

	// Delete each tag
	deletedCount := 0
	errors := []string{}

	for _, tag := range tags {
		// Get the digest for this tag
		_, digest, err := registryClient.GetManifest(repo, tag)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Failed to get digest for %s:%s - %v", repo, tag, err))
			continue
		}

		// Delete using the digest
		if err := registryClient.DeleteImage(repo, digest); err != nil {
			errors = append(errors, fmt.Sprintf("Failed to delete %s:%s - %v", repo, tag, err))
			continue
		}

		deletedCount++
	}

	// Return success or partial success message
	if len(errors) > 0 && deletedCount == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("Failed to delete any tags from repository %s: %v", repo, errors),
		})
		return
	}

	message := fmt.Sprintf("Successfully deleted all %d tag(s) from '%s'. The repository name will still appear in the list until you run registry cleanup.", deletedCount, repo)
	if len(errors) > 0 {
		message = fmt.Sprintf("Partially deleted repository '%s' (%d/%d tags succeeded). Some errors occurred: %v", repo, deletedCount, len(tags), errors)
	}

	c.JSON(http.StatusOK, gin.H{
		"message": message,
	})
}
