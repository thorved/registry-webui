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
	var allOutput bytes.Buffer

	// Step 1: Clean up corrupted tags (where blob is missing)
	fmt.Fprintln(&allOutput, "=== Step 1: Cleaning corrupted tags ===")

	// Simple script to find and remove orphaned tags
	cleanupScript := `
#!/bin/sh
cd /var/lib/registry/docker/registry/v2/repositories || exit 1
count=0
for repo in */; do
    repo="${repo%/}"
    [ -d "$repo/_manifests/tags" ] || continue
    
    for tag_dir in "$repo/_manifests/tags"/*; do
        [ -d "$tag_dir" ] || continue
        tag=$(basename "$tag_dir")
        link_file="$tag_dir/current/link"
        
        if [ -f "$link_file" ]; then
            digest=$(cat "$link_file")
            # Convert sha256:abc123... to sha256/ab/c123...
            prefix="${digest:7:2}"
            rest="${digest:9}"
            blob_path="/var/lib/registry/docker/registry/v2/blobs/sha256/$prefix/$rest/data"
            
            if [ ! -f "$blob_path" ]; then
                echo "Found corrupted tag: $repo:$tag (digest $digest missing)"
                rm -rf "$tag_dir"
                echo "  Removed tag directory: $tag_dir"
                count=$((count + 1))
            fi
        fi
    done
done
echo "Cleaned up $count corrupted tag(s)"
`

	cleanupCmd := exec.Command("docker", "exec", "docker-registry", "sh", "-c", cleanupScript)
	var cleanupOut, cleanupErr bytes.Buffer
	cleanupCmd.Stdout = &cleanupOut
	cleanupCmd.Stderr = &cleanupErr

	if err := cleanupCmd.Run(); err != nil {
		fmt.Fprintf(&allOutput, "Cleanup error: %v\n%s\n", err, cleanupErr.String())
	}
	fmt.Fprintln(&allOutput, cleanupOut.String())

	// Step 2: Run garbage collection
	fmt.Fprintln(&allOutput, "\n=== Step 2: Running garbage collection ===")
	gcCmd := exec.Command("docker", "exec", "docker-registry", "registry", "garbage-collect", "/etc/docker/registry/config.yml", "--delete-untagged")

	var gcOut, gcErr bytes.Buffer
	gcCmd.Stdout = &gcOut
	gcCmd.Stderr = &gcErr

	if err := gcCmd.Run(); err != nil {
		fmt.Fprintf(&allOutput, "GC error: %v\n%s\n", err, gcErr.String())
	}

	gcOutput := gcOut.String()
	if gcOutput != "" {
		fmt.Fprintln(&allOutput, gcOutput)
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Cleanup completed. Corrupted tags removed and garbage collection finished.",
		"output":  allOutput.String(),
	})
}
