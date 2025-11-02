package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ACLEntry represents a single access control rule
type ACLEntry struct {
	Match   ACLMatch `json:"match"`
	Actions []string `json:"actions"`
	Comment string   `json:"comment,omitempty"`
}

// ACLMatch defines the matching criteria for an ACL entry
type ACLMatch struct {
	Account string `json:"account,omitempty"` // Username or regex pattern (deprecated, use Role)
	Role    string `json:"role,omitempty"`    // User role (admin, developer, readonly, custom)
	Type    string `json:"type,omitempty"`    // Resource type (e.g., "repository", "registry")
	Name    string `json:"name,omitempty"`    // Repository name or pattern
}

// ACL manages access control lists
type ACL struct {
	Entries   []ACLEntry
	UserStore *UserStore // Reference to user store for role lookup
}

// NewACL creates a new ACL from a file
func NewACL(filePath string, userStore *UserStore) (*ACL, error) {
	data, err := os.ReadFile(filePath)
	var entries []ACLEntry
	if err != nil {
		if os.IsNotExist(err) {
			// Create parent directory if needed
			dir := filepath.Dir(filePath)
			if err := os.MkdirAll(dir, 0755); err != nil {
				return nil, fmt.Errorf("failed to create acl directory: %v", err)
			}

			// Default ACL entries (role-based)
			entries = []ACLEntry{
				{
					Match: ACLMatch{Role: "admin"},
					Actions: []string{"*"},
					Comment: "Admins have full access",
				},
				{
					Match: ACLMatch{Role: "developer", Type: "registry", Name: "catalog"},
					Actions: []string{"*"},
					Comment: "Developers can list repositories (catalog requires wildcard)",
				},
				{
					Match: ACLMatch{Role: "developer"},
					Actions: []string{"push", "pull"},
					Comment: "Developers can push and pull repositories",
				},
				{
					Match: ACLMatch{Role: "readonly", Type: "registry", Name: "catalog"},
					Actions: []string{"*"},
					Comment: "Read-only users can list repositories",
				},
				{
					Match: ACLMatch{Role: "readonly"},
					Actions: []string{"pull"},
					Comment: "Read-only users can only pull repositories",
				},
			}

			// Persist default ACL to file
			out, jerr := json.MarshalIndent(entries, "", "  ")
			if jerr != nil {
				return nil, fmt.Errorf("failed to marshal default ACL: %v", jerr)
			}
			if werr := os.WriteFile(filePath, out, 0644); werr != nil {
				return nil, fmt.Errorf("failed to write default ACL file: %v", werr)
			}
			fmt.Printf("✓ Created default ACL at %s\n", filePath)
		} else {
			return nil, fmt.Errorf("failed to read ACL file: %v", err)
		}
	} else {
		if jerr := json.Unmarshal(data, &entries); jerr != nil {
			return nil, fmt.Errorf("failed to parse ACL file: %v", jerr)
		}
	}

	return &ACL{
		Entries:   entries,
		UserStore: userStore,
	}, nil
}

// GetPermissions returns the allowed actions for a user on a resource
// Checks both role-based and account-based rules
func (a *ACL) GetPermissions(username, resourceType, resourceName string) []string {
	var allowedActions []string
	actionsMap := make(map[string]bool)
	exactMatchFound := false

	// Get user's role if user store is available
	var userRole string
	if a.UserStore != nil {
		userRole = a.UserStore.GetUserRole(username)
	}

	// First pass: look for role-based or exact account matches (not regex)
	for _, entry := range a.Entries {
		// Check role-based match first (preferred)
		if entry.Match.Role != "" && userRole != "" && entry.Match.Role == userRole {
			if a.matchesEntry(entry, username, userRole, resourceType, resourceName) {
				exactMatchFound = true
				for _, action := range entry.Actions {
					actionsMap[action] = true
				}
			}
		} else if entry.Match.Account != "" && !isRegexPattern(entry.Match.Account) {
			if entry.Match.Account == username {
				if a.matchesEntry(entry, username, userRole, resourceType, resourceName) {
					exactMatchFound = true
					for _, action := range entry.Actions {
						actionsMap[action] = true
					}
					// Found exact match, use only this rule
					break
				}
			}
		}
	}

	// If no exact match, apply all matching regex/wildcard rules
	if !exactMatchFound {
		for _, entry := range a.Entries {
			if a.matchesEntry(entry, username, userRole, resourceType, resourceName) {
				for _, action := range entry.Actions {
					actionsMap[action] = true
				}
			}
		}
	}

	for action := range actionsMap {
		allowedActions = append(allowedActions, action)
	}

	return allowedActions
}

// isRegexPattern checks if a pattern is a regex (enclosed in forward slashes)
func isRegexPattern(pattern string) bool {
	return len(pattern) > 2 && pattern[0] == '/' && pattern[len(pattern)-1] == '/'
}

// matchesEntry checks if an entry matches the given criteria
func (a *ACL) matchesEntry(entry ACLEntry, username, userRole, resourceType, resourceName string) bool {
	// Check role match (preferred over account match)
	if entry.Match.Role != "" {
		if userRole == "" || entry.Match.Role != userRole {
			return false
		}
	}

	// Check account match (for backward compatibility)
	if entry.Match.Account != "" {
		if !a.matchPattern(entry.Match.Account, username) {
			return false
		}
	}

	// Check type match
	if entry.Match.Type != "" && entry.Match.Type != resourceType {
		return false
	}

	// Check name match (repository name)
	if entry.Match.Name != "" {
		if !a.matchPattern(entry.Match.Name, resourceName) {
			return false
		}
	}

	return true
}

// matchPattern matches a string against a pattern (supports wildcards and regex)
func (a *ACL) matchPattern(pattern, value string) bool {
	// Empty username for anonymous
	if pattern == "" && value == "" {
		return true
	}

	// Direct match
	if pattern == value {
		return true
	}

	// Regex pattern (enclosed in /.+/)
	if strings.HasPrefix(pattern, "/") && strings.HasSuffix(pattern, "/") {
		regexPattern := strings.Trim(pattern, "/")
		matched, err := regexp.MatchString(regexPattern, value)
		if err == nil && matched {
			return true
		}
	}

	// Wildcard pattern (convert * to .*)
	if strings.Contains(pattern, "*") {
		wildcardPattern := "^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), "\\*", ".*") + "$"
		matched, err := regexp.MatchString(wildcardPattern, value)
		if err == nil && matched {
			return true
		}
	}

	// Variable substitution ${account}
	if strings.Contains(pattern, "${account}") {
		expandedPattern := strings.ReplaceAll(pattern, "${account}", value)
		if expandedPattern == value {
			return true
		}
		// Also check if it's a prefix match
		if strings.HasSuffix(expandedPattern, "/*") {
			prefix := strings.TrimSuffix(expandedPattern, "/*")
			if strings.HasPrefix(value, prefix+"/") || value == prefix {
				return true
			}
		}
	}

	return false
}

// CanPull checks if a user can pull from a repository
func (a *ACL) CanPull(username, repo string) bool {
	actions := a.GetPermissions(username, "repository", repo)
	for _, action := range actions {
		if action == "pull" || action == "*" {
			return true
		}
	}
	return false
}

// CanPush checks if a user can push to a repository
func (a *ACL) CanPush(username, repo string) bool {
	actions := a.GetPermissions(username, "repository", repo)
	for _, action := range actions {
		if action == "push" || action == "*" {
			return true
		}
	}
	return false
}

// LoadACL is an alias for NewACL for backwards compatibility
func LoadACL(filePath string, userStore *UserStore) (*ACL, error) {
	return NewACL(filePath, userStore)
}

// EnsureAdminExists checks if the admin user exists in ACL, and adds it if missing
func EnsureAdminExists(aclPath, username string) error {
	// Read ACL file
	data, err := os.ReadFile(aclPath)
	if err != nil {
		return fmt.Errorf("failed to read ACL file: %v", err)
	}

	var entries []ACLEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("failed to parse ACL file: %v", err)
	}

	// Check if admin user already exists
	for _, entry := range entries {
		if entry.Match.Account == username {
			// Admin already exists in ACL
			return nil
		}
	}

	// Admin doesn't exist, add it as the first entry
	adminEntry := ACLEntry{
		Match: ACLMatch{
			Account: username,
		},
		Actions: []string{"*"},
		Comment: fmt.Sprintf("Admin user %s - full access (auto-created)", username),
	}

	// Prepend admin entry to the beginning
	entries = append([]ACLEntry{adminEntry}, entries...)

	// Save back to file
	newData, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal ACL: %v", err)
	}

	if err := os.WriteFile(aclPath, newData, 0644); err != nil {
		return fmt.Errorf("failed to write ACL file: %v", err)
	}

	fmt.Printf("✓ Added default admin user '%s' to ACL with full permissions\n", username)
	return nil
}
