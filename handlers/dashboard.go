package handlers

import (
	"fmt"
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

	if username != nil && password != nil {
		return registry.NewClient(h.Config.RegistryURL, username.(string), password.(string))
	}

	// Fallback to default credentials if session doesn't have them
	return h.Registry
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
	registryClient := h.getRegistryClient(c)
	repositories, err := registryClient.ListRepositories()
	if err != nil {
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
			continue
		}
		// Only include repos that have at least one tag
		if len(tags) > 0 {
			filteredRepos = append(filteredRepos, repo)
		}
	}

	c.HTML(http.StatusOK, "repositories.html", gin.H{
		"repositories": filteredRepos,
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

	c.HTML(http.StatusOK, "repository_detail.html", gin.H{
		"repository": repo,
		"tags":       tags,
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
