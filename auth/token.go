package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenService handles JWT token generation for Docker Registry
type TokenService struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	issuer     string
	expiration time.Duration
	acl        *ACL
}

// TokenClaims represents the JWT claims for Docker Registry tokens
type TokenClaims struct {
	Access []AccessEntry `json:"access"`
	jwt.RegisteredClaims
}

// AccessEntry represents a single access entry in the token
type AccessEntry struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

// NewTokenService creates a new token service
func NewTokenService(privateKeyPath, issuer string, expiration time.Duration, acl *ACL) (*TokenService, error) {
	var privateKey *rsa.PrivateKey
	var publicKey *rsa.PublicKey

	certPath := "/certs/token.crt"

	// Try to load existing private key
	if _, err := os.Stat(privateKeyPath); err == nil {
		fmt.Printf("Loading existing private key from: %s\n", privateKeyPath)
		keyData, err := os.ReadFile(privateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key: %v", err)
		}

		block, _ := pem.Decode(keyData)
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM block from private key")
		}

		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %v", err)
		}

		publicKey = &privateKey.PublicKey

		// Check if certificate exists, generate if not
		if _, err := os.Stat(certPath); os.IsNotExist(err) {
			fmt.Printf("Certificate not found, generating new one...\n")
			if err := generateCertificate(privateKey, certPath, issuer); err != nil {
				return nil, fmt.Errorf("failed to generate certificate: %v", err)
			}
		} else {
			fmt.Printf("Certificate already exists at: %s\n", certPath)
		}
	} else {
		// Generate new RSA key pair
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA key: %v", err)
		}

		privateKey = key
		publicKey = &key.PublicKey

		// Save private key
		privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		privateKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyBytes,
		})

		// Ensure directory for private key exists
		keyDir := filepath.Dir(privateKeyPath)
		if err := os.MkdirAll(keyDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory for private key: %v", err)
		}

		if err := os.WriteFile(privateKeyPath, privateKeyPEM, 0600); err != nil {
			return nil, fmt.Errorf("failed to save private key: %v", err)
		}

		// Generate self-signed certificate for the public key
		certPath := "/certs/token.crt"
		fmt.Printf("Generating certificate at: %s\n", certPath)
		if err := generateCertificate(privateKey, certPath, issuer); err != nil {
			return nil, fmt.Errorf("failed to generate certificate: %v", err)
		}
		fmt.Printf("Certificate generated successfully at: %s\n", certPath)

		// Save public key (for reference)
		publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal public key: %v", err)
		}

		publicKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyBytes,
		})

		publicKeyPath := privateKeyPath + ".pub"
		if err := os.WriteFile(publicKeyPath, publicKeyPEM, 0644); err != nil {
			return nil, fmt.Errorf("failed to save public key: %v", err)
		}
	}

	// Create TokenService instance
	ts := &TokenService{
		privateKey: privateKey,
		publicKey:  publicKey,
		issuer:     issuer,
		expiration: expiration,
		acl:        acl,
	}

	// Generate and save JWKS file
	jwksPath := "/certs/jwks.json"
	fmt.Printf("Generating JWKS file at: %s\n", jwksPath)
	if err := ts.SaveJWKS(jwksPath); err != nil {
		return nil, fmt.Errorf("failed to save JWKS: %v", err)
	}
	fmt.Printf("JWKS file generated successfully\n")

	return ts, nil
}

// generateCertificate creates a self-signed X.509 certificate
func generateCertificate(privateKey *rsa.PrivateKey, certPath, issuer string) error {
	fmt.Printf("Creating certificate directory...\n")
	// Ensure directory exists
	certDir := filepath.Dir(certPath)
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("failed to create cert directory: %v", err)
	}
	fmt.Printf("Certificate directory created: %s\n", certDir)

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %v", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // Valid for 1 year

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Docker Registry"},
			CommonName:   issuer,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	// Create self-signed certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %v", err)
	}

	// Save certificate
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	fmt.Printf("Writing certificate to: %s\n", certPath)
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to save certificate: %v", err)
	}
	fmt.Printf("Certificate saved successfully\n")

	return nil
}

// GenerateToken generates a JWT token for the given user and scopes
func (ts *TokenService) GenerateToken(username, service string, scopes []string) (string, error) {
	now := time.Now()

	// Parse scopes and build access entries
	accessEntries := make([]AccessEntry, 0)

	for _, scope := range scopes {
		// Scope format: "repository:repo-name:pull,push"
		parts := splitScope(scope)
		if len(parts) != 3 {
			continue
		}

		resourceType := parts[0]
		resourceName := parts[1]
		requestedActions := splitActions(parts[2])

		// Get allowed actions from ACL
		allowedActions := ts.acl.GetPermissions(username, resourceType, resourceName)
		log.Printf("[TOKEN] User=%s, Type=%s, Name=%s, RequestedActions=%v, AllowedActions=%v",
			username, resourceType, resourceName, requestedActions, allowedActions)

		// Filter requested actions based on ACL
		grantedActions := make([]string, 0)

		// Check if wildcard permission is granted
		hasWildcard := false
		for _, allowed := range allowedActions {
			if allowed == "*" {
				hasWildcard = true
				break
			}
		}

		// Check if wildcard is requested
		requestsWildcard := false
		for _, action := range requestedActions {
			if action == "*" {
				requestsWildcard = true
				break
			}
		}

		if hasWildcard {
			// User has wildcard permission - grant all requested actions
			grantedActions = requestedActions
			log.Printf("[TOKEN] Wildcard permission granted, granting all: %v", grantedActions)
		} else if requestsWildcard {
			// Request wants wildcard but user doesn't have it
			// Grant the user's actual allowed actions (not the wildcard)
			// The registry will accept the token if it has at least one valid action
			grantedActions = allowedActions
			log.Printf("[TOKEN] Wildcard requested, user doesn't have wildcard, granting user's actual permissions: %v", grantedActions)
		} else {
			// Filter based on specific allowed actions
			for _, action := range requestedActions {
				for _, allowed := range allowedActions {
					if action == allowed {
						grantedActions = append(grantedActions, action)
						break
					}
				}
			}
			log.Printf("[TOKEN] Filtered permissions, granted: %v", grantedActions)
		} // Only add entry if there are granted actions
		if len(grantedActions) > 0 {
			accessEntries = append(accessEntries, AccessEntry{
				Type:    resourceType,
				Name:    resourceName,
				Actions: grantedActions,
			})
		}
	}

	// Create JWT claims
	claims := TokenClaims{
		Access: accessEntries,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    ts.issuer,
			Subject:   username,
			Audience:  jwt.ClaimStrings{service},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ts.expiration)),
		},
	}

	// Create and sign token with kid header
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Add kid header to match JWKS
	token.Header["kid"] = ts.issuer

	tokenString, err := token.SignedString(ts.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %v", err)
	}

	return tokenString, nil
}

// GenerateTokenWithPermissions generates a JWT token with specific permissions
// This is used for personal access tokens that have limited permissions
func (ts *TokenService) GenerateTokenWithPermissions(username, service string, scopes []string, allowedPermissions []string, allowedRepos []string) (string, error) {
	now := time.Now()

	// Parse scopes and build access entries
	accessEntries := make([]AccessEntry, 0)

	for _, scope := range scopes {
		// Scope format: "repository:repo-name:pull,push"
		parts := splitScope(scope)
		if len(parts) != 3 {
			continue
		}

		resourceType := parts[0]
		resourceName := parts[1]
		requestedActions := splitActions(parts[2])

		// Check if this repository is allowed by the personal token
		repoAllowed := false
		for _, pattern := range allowedRepos {
			if pattern == "*" || matchRepoPattern(pattern, resourceName) {
				repoAllowed = true
				break
			}
		}

		if !repoAllowed {
			log.Printf("[TOKEN-PAT] Repository %s not allowed by personal token", resourceName)
			continue
		}

		// Filter requested actions based on personal token permissions
		grantedActions := make([]string, 0)

		// Check if wildcard permission is in the token
		hasWildcard := false
		for _, allowed := range allowedPermissions {
			if allowed == "*" {
				hasWildcard = true
				break
			}
		}

		if hasWildcard {
			// Token has wildcard permission - grant all requested actions
			grantedActions = requestedActions
			log.Printf("[TOKEN-PAT] User=%s, Type=%s, Name=%s, Wildcard granted: %v", username, resourceType, resourceName, grantedActions)
		} else {
			// Filter based on specific allowed actions from the personal token
			for _, action := range requestedActions {
				// Handle wildcard request
				if action == "*" {
					// Grant all permissions the token has
					grantedActions = allowedPermissions
					break
				}

				for _, allowed := range allowedPermissions {
					if action == allowed {
						grantedActions = append(grantedActions, action)
						break
					}
				}
			}
			log.Printf("[TOKEN-PAT] User=%s, Type=%s, Name=%s, Requested=%v, Granted=%v", username, resourceType, resourceName, requestedActions, grantedActions)
		}

		// Only add entry if there are granted actions
		if len(grantedActions) > 0 {
			accessEntries = append(accessEntries, AccessEntry{
				Type:    resourceType,
				Name:    resourceName,
				Actions: grantedActions,
			})
		}
	}

	// Create JWT claims
	claims := TokenClaims{
		Access: accessEntries,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    ts.issuer,
			Subject:   username,
			Audience:  jwt.ClaimStrings{service},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ts.expiration)),
		},
	}

	// Create and sign token with kid header
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Add kid header to match JWKS
	token.Header["kid"] = ts.issuer

	tokenString, err := token.SignedString(ts.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %v", err)
	}

	return tokenString, nil
}

// matchRepoPattern checks if a repository name matches a pattern
// Supports wildcards: "myapp/*" matches "myapp/frontend", "myapp/backend", etc.
func matchRepoPattern(pattern, repoName string) bool {
	if pattern == repoName {
		return true
	}

	// Handle wildcard patterns
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(repoName, prefix+"/")
	}

	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(repoName, prefix)
	}

	return false
}

// GetPublicKey returns the public key in PEM format
func (ts *TokenService) GetPublicKey() (string, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(ts.publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %v", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return string(publicKeyPEM), nil
}

// splitScope splits a scope string into its components
func splitScope(scope string) []string {
	// Format: "repository:repo-name:pull,push"
	parts := make([]string, 0, 3)

	firstColon := -1
	secondColon := -1

	for i, c := range scope {
		if c == ':' {
			if firstColon == -1 {
				firstColon = i
			} else if secondColon == -1 {
				secondColon = i
				break
			}
		}
	}

	if firstColon == -1 {
		return parts
	}

	parts = append(parts, scope[:firstColon])

	if secondColon == -1 {
		parts = append(parts, scope[firstColon+1:])
		return parts
	}

	parts = append(parts, scope[firstColon+1:secondColon])
	parts = append(parts, scope[secondColon+1:])

	return parts
}

// splitActions splits comma-separated actions
func splitActions(actions string) []string {
	result := make([]string, 0)
	for _, action := range splitByComma(actions) {
		if action != "" {
			result = append(result, action)
		}
	}
	return result
}

func splitByComma(s string) []string {
	var result []string
	current := ""
	for _, c := range s {
		if c == ',' {
			result = append(result, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

// GetJWKS returns the public key in JWKS format
func (ts *TokenService) GetJWKS() map[string]interface{} {
	// Encode modulus and exponent in base64 URL encoding
	n := base64.RawURLEncoding.EncodeToString(ts.publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(ts.publicKey.E)).Bytes())

	return map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": ts.issuer,
				"n":   n,
				"e":   e,
			},
		},
	}
}

// SaveJWKS saves the JWKS to a file
func (ts *TokenService) SaveJWKS(path string) error {
	jwks := ts.GetJWKS()

	// Marshal to JSON with indentation
	data, err := json.MarshalIndent(jwks, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JWKS: %v", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	// Write to file
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write JWKS file: %v", err)
	}

	return nil
}

// CanPush checks if a user can push to a given repository via the ACL
func (ts *TokenService) CanPush(username, repo string) bool {
	if ts.acl == nil {
		return false
	}
	return ts.acl.CanPush(username, repo)
}

// CanPull checks if a user can pull from a given repository via the ACL
func (ts *TokenService) CanPull(username, repo string) bool {
	if ts.acl == nil {
		return false
	}
	return ts.acl.CanPull(username, repo)
}

// IsAdmin returns true when the user has wildcard/admin permissions
func (ts *TokenService) IsAdmin(username string) bool {
	if ts.acl == nil {
		return false
	}
	// Check if user has '*' actions on ANY repository (not just catalog)
	// This should only match actual admin accounts defined in ACL
	perms := ts.acl.GetPermissions(username, "repository", "*")
	for _, p := range perms {
		if p == "*" {
			return true
		}
	}
	// Also check if they explicitly have push+pull+delete which is essentially admin
	hasPush := false
	hasPull := false
	hasDelete := false
	for _, p := range perms {
		if p == "push" {
			hasPush = true
		}
		if p == "pull" {
			hasPull = true
		}
		if p == "delete" {
			hasDelete = true
		}
	}
	return hasPush && hasPull && hasDelete
}

// SetACL updates the ACL used by the TokenService
func (ts *TokenService) SetACL(acl *ACL) {
	ts.acl = acl
}
