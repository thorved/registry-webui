package handlers

import (
	"bytes"
	"fmt"
	"net/http"
	"os/exec"

	"github.com/gin-gonic/gin"
)

// RunGarbageCollection triggers registry garbage collection
func (h *Handler) RunGarbageCollection(c *gin.Context) {
	// Run garbage collection on the registry container
	// Use the actual config location in registry:3 image
	cmd := exec.Command("docker", "exec", "docker-registry", "registry", "garbage-collect", "/etc/distribution/config.yml", "--delete-untagged")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("Failed to run garbage collection: %v - %s", err, stderr.String()),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Garbage collection completed successfully. Empty repositories have been removed.",
		"output":  stdout.String(),
	})
}
