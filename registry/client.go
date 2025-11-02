package registry

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client represents a Docker Registry v2 API client
type Client struct {
	baseURL      string
	username     string
	password     string
	client       *http.Client
	tokenService string               // Token service URL for authentication
	tokenCache   map[string]string    // Cached tokens per scope
	expiryCache  map[string]time.Time // Token expiry times per scope
}

// Repository represents a registry repository
type Repository struct {
	Name string `json:"name"`
}

// Tag represents an image tag
type Tag struct {
	Name string `json:"name"`
}

// Manifest represents image manifest information
type Manifest struct {
	SchemaVersion int                    `json:"schemaVersion"`
	MediaType     string                 `json:"mediaType"`
	Config        ManifestConfig         `json:"config"`
	Layers        []ManifestLayer        `json:"layers"`
	Architecture  string                 `json:"architecture,omitempty"`
	OS            string                 `json:"os,omitempty"`
	RawData       map[string]interface{} `json:"-"`
	// OCI-specific fields
	ArtifactType string            `json:"artifactType,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

// ManifestConfig represents the config in a manifest
type ManifestConfig struct {
	MediaType string `json:"mediaType"`
	Size      int64  `json:"size"`
	Digest    string `json:"digest"`
}

// ManifestLayer represents a layer in a manifest
type ManifestLayer struct {
	MediaType string `json:"mediaType"`
	Size      int64  `json:"size"`
	Digest    string `json:"digest"`
}

// ImageInfo represents detailed image information
type ImageInfo struct {
	Repository   string
	Tag          string
	Digest       string
	Size         int64
	Layers       int
	Architecture string
	CreatedAt    time.Time
}

// NewClient creates a new registry client
func NewClient(baseURL, username, password string) *Client {
	return &Client{
		baseURL:      strings.TrimSuffix(baseURL, "/"),
		username:     username,
		password:     password,
		tokenService: "http://localhost:8080", // Internal token service
		tokenCache:   make(map[string]string),
		expiryCache:  make(map[string]time.Time),
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// getToken requests a token from the auth service
func (c *Client) getToken(scope string) (string, error) {
	// Check if we have a valid cached token for this scope
	if token, ok := c.tokenCache[scope]; ok {
		if expiry, ok := c.expiryCache[scope]; ok && time.Now().Before(expiry) {
			return token, nil
		}
	}

	// Request new token
	tokenURL := fmt.Sprintf("%s/auth?service=registry&scope=%s", c.tokenService, scope)
	req, err := http.NewRequest("GET", tokenURL, nil)
	if err != nil {
		return "", err
	}

	if c.username != "" && c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token request failed: %d - %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		Token     string `json:"token"`
		ExpiresIn int    `json:"expires_in"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}

	// Cache token for this scope
	c.tokenCache[scope] = tokenResp.Token
	c.expiryCache[scope] = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	return tokenResp.Token, nil
}

// doRequest performs an HTTP request with authentication
func (c *Client) doRequest(method, path string, acceptHeader string) (*http.Response, error) {
	return c.doRequestWithScope(method, path, acceptHeader, "")
}

// doRequestWithScope performs an HTTP request with token authentication
func (c *Client) doRequestWithScope(method, path string, acceptHeader string, scope string) (*http.Response, error) {
	url := c.baseURL + path
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	// Try with token authentication first if scope is provided
	if scope != "" {
		token, err := c.getToken(scope)
		if err == nil && token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	} else if c.username != "" && c.password != "" {
		// Fallback to basic auth
		req.SetBasicAuth(c.username, c.password)
	}

	if acceptHeader != "" {
		req.Header.Set("Accept", acceptHeader)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	// If we get 401, try to get a token and retry
	if resp.StatusCode == http.StatusUnauthorized && scope == "" {
		resp.Body.Close()

		// Extract scope from WWW-Authenticate header if available
		authHeader := resp.Header.Get("Www-Authenticate")
		if strings.Contains(authHeader, "Bearer") {
			// Retry with catalog scope for listing
			return c.doRequestWithScope(method, path, acceptHeader, "registry:catalog:*")
		}
	}

	return resp, nil
}

// ListRepositories returns all repositories in the registry
func (c *Client) ListRepositories() ([]string, error) {
	// Use catalog scope for listing repositories
	resp, err := c.doRequestWithScope("GET", "/v2/_catalog", "application/json", "registry:catalog:*")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("registry API error: %d - %s", resp.StatusCode, string(body))
	}

	var result struct {
		Repositories []string `json:"repositories"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Repositories, nil
}

// ListTags returns all tags for a repository
func (c *Client) ListTags(repository string) ([]string, error) {
	path := fmt.Sprintf("/v2/%s/tags/list", repository)
	scope := fmt.Sprintf("repository:%s:pull", repository)
	resp, err := c.doRequestWithScope("GET", path, "application/json", scope)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("registry API error: %d - %s", resp.StatusCode, string(body))
	}

	var result struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Tags, nil
}

// GetManifest retrieves the manifest for a specific image tag
func (c *Client) GetManifest(repository, tag string) (*Manifest, string, error) {
	path := fmt.Sprintf("/v2/%s/manifests/%s", repository, tag)
	scope := fmt.Sprintf("repository:%s:pull", repository)

	// CRITICAL: Request the specific manifest media type to get the correct digest
	// Per Docker Distribution docs: "For registry versions 2.3+, use Accept: application/vnd.docker.distribution.manifest.v2+json
	// when HEAD or GETting the manifest to obtain the correct digest."
	// We must request the manifest in the format it's stored to get the matching digest
	acceptHeader := "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json"

	resp, err := c.doRequestWithScope("GET", path, acceptHeader, scope)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, "", fmt.Errorf("registry API error: %d - %s", resp.StatusCode, string(body))
	}

	// Get the digest from the Docker-Content-Digest header
	// This is the canonical digest that the registry uses internally
	digest := resp.Header.Get("Docker-Content-Digest")

	// Read the body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}

	// If digest is still empty, it means the registry didn't return it
	// This shouldn't happen with modern registries, but we can fall back to HEAD request
	if digest == "" {
		fmt.Printf("[REGISTRY] Warning: No Docker-Content-Digest header found for %s:%s\n", repository, tag)
		fmt.Printf("[REGISTRY] Content-Type: %s\n", resp.Header.Get("Content-Type"))

		// Try a HEAD request which should always include the digest
		headResp, err := c.doRequestWithScope("HEAD", path, acceptHeader, scope)
		if err == nil {
			digest = headResp.Header.Get("Docker-Content-Digest")
			headResp.Body.Close()
			fmt.Printf("[REGISTRY] Got digest from HEAD request: %s\n", digest)
		}

		// If still no digest, we have a problem
		if digest == "" {
			return nil, "", fmt.Errorf("registry did not return Docker-Content-Digest header")
		}
	}

	var manifest Manifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return nil, "", err
	}

	// Handle both OCI and Docker manifest formats
	// Set default values if not present
	if manifest.Architecture == "" {
		// Try to parse from raw data if available
		var rawManifest map[string]interface{}
		if err := json.Unmarshal(body, &rawManifest); err == nil {
			if config, ok := rawManifest["config"].(map[string]interface{}); ok {
				if arch, ok := config["architecture"].(string); ok {
					manifest.Architecture = arch
				}
			}
		}
	}

	return &manifest, digest, nil
}

// GetImageInfo retrieves detailed information about an image
func (c *Client) GetImageInfo(repository, tag string) (*ImageInfo, error) {
	manifest, digest, err := c.GetManifest(repository, tag)
	if err != nil {
		return nil, err
	}

	var totalSize int64
	for _, layer := range manifest.Layers {
		totalSize += layer.Size
	}

	// Get architecture from manifest or fetch from config blob
	architecture := manifest.Architecture
	if architecture == "" && manifest.Config.Digest != "" {
		// Try to fetch architecture from config blob
		configInfo, err := c.GetBlobConfig(repository, manifest.Config.Digest)
		if err == nil && configInfo != nil {
			architecture = configInfo.Architecture
		}
	}

	info := &ImageInfo{
		Repository:   repository,
		Tag:          tag,
		Digest:       digest,
		Size:         totalSize,
		Layers:       len(manifest.Layers),
		Architecture: architecture,
		CreatedAt:    time.Now(), // Would need to parse from config blob
	}

	return info, nil
}

// BlobConfig represents the configuration from a config blob
type BlobConfig struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Created      string `json:"created"`
}

// GetBlobConfig retrieves and parses a config blob
func (c *Client) GetBlobConfig(repository, digest string) (*BlobConfig, error) {
	path := fmt.Sprintf("/v2/%s/blobs/%s", repository, digest)
	resp, err := c.doRequest("GET", path, "application/json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch config blob: %d", resp.StatusCode)
	}

	var config BlobConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

// DeleteImage deletes an image by its digest
func (c *Client) DeleteImage(repository, digest string) error {
	path := fmt.Sprintf("/v2/%s/manifests/%s", repository, digest)
	scope := fmt.Sprintf("repository:%s:delete", repository)
	resp, err := c.doRequestWithScope("DELETE", path, "", scope)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete image: %d - %s", resp.StatusCode, string(body))
	}

	return nil
}

// CheckHealth checks if the registry is accessible
func (c *Client) CheckHealth() error {
	resp, err := c.doRequest("GET", "/v2/", "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registry health check failed: %d", resp.StatusCode)
	}

	return nil
}
