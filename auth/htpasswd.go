package auth

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// HtpasswdAuth handles htpasswd file authentication
type HtpasswdAuth struct {
	filePath string
	users    map[string]string // username -> hashed password
}

// NewHtpasswdAuth creates a new htpasswd authenticator
func NewHtpasswdAuth(filePath string) (*HtpasswdAuth, error) {
	auth := &HtpasswdAuth{
		filePath: filePath,
		users:    make(map[string]string),
	}

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		fmt.Printf("Password file not found at %s, creating with default admin user\n", filePath)

		// Create directory if it doesn't exist
		dir := strings.TrimSuffix(filePath, "/registry.password")
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create auth directory: %v", err)
		}

		// Create default admin user (admin/admin)
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("failed to hash default admin password: %v", err)
		}

		auth.users["admin"] = string(hashedPassword)

		// Save the file with default admin user
		if err := auth.saveFile(); err != nil {
			return nil, fmt.Errorf("failed to create default password file: %v", err)
		}

		fmt.Printf("✓ Default admin user created (username: admin, password: admin)\n")
		fmt.Printf("⚠ IMPORTANT: Please change the default admin password immediately!\n")
	} else if err != nil {
		return nil, fmt.Errorf("failed to check password file: %v", err)
	} else {
		// File exists, load it
		if err := auth.loadFile(); err != nil {
			return nil, err
		}
	}

	return auth, nil
}

// loadFile reads and parses the htpasswd file
func (h *HtpasswdAuth) loadFile() error {
	file, err := os.Open(h.filePath)
	if err != nil {
		return fmt.Errorf("failed to open htpasswd file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		username := parts[0]
		password := parts[1]
		h.users[username] = password
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading htpasswd file: %v", err)
	}

	return nil
}

// Authenticate verifies username and password
func (h *HtpasswdAuth) Authenticate(username, password string) bool {
	hashedPassword, exists := h.users[username]
	if !exists {
		return false
	}

	// Check if it's bcrypt hash (starts with $2a$, $2b$, or $2y$)
	if strings.HasPrefix(hashedPassword, "$2") {
		err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
		return err == nil
	}

	// Add support for other hash types if needed (MD5, SHA1, etc.)
	return false
}

// Reload reloads the htpasswd file
func (h *HtpasswdAuth) Reload() error {
	h.users = make(map[string]string)
	return h.loadFile()
}

// UserExists checks if a username exists
func (h *HtpasswdAuth) UserExists(username string) bool {
	_, exists := h.users[username]
	return exists
}

// ListUsers returns all usernames
func (h *HtpasswdAuth) ListUsers() []string {
	users := make([]string, 0, len(h.users))
	for username := range h.users {
		users = append(users, username)
	}
	return users
}

// AddUser adds a new user with bcrypt password
func (h *HtpasswdAuth) AddUser(username, password string) error {
	if h.UserExists(username) {
		return fmt.Errorf("user already exists")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}

	h.users[username] = string(hashedPassword)
	return h.saveFile()
}

// UpdatePassword updates an existing user's password
func (h *HtpasswdAuth) UpdatePassword(username, newPassword string) error {
	if !h.UserExists(username) {
		return fmt.Errorf("user does not exist")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}

	h.users[username] = string(hashedPassword)
	return h.saveFile()
}

// DeleteUser removes a user
func (h *HtpasswdAuth) DeleteUser(username string) error {
	if !h.UserExists(username) {
		return fmt.Errorf("user does not exist")
	}

	delete(h.users, username)
	return h.saveFile()
}

// saveFile writes the users map back to the htpasswd file
func (h *HtpasswdAuth) saveFile() error {
	file, err := os.Create(h.filePath)
	if err != nil {
		return fmt.Errorf("failed to create htpasswd file: %v", err)
	}
	defer file.Close()

	for username, hashedPassword := range h.users {
		_, err := fmt.Fprintf(file, "%s:%s\n", username, hashedPassword)
		if err != nil {
			return fmt.Errorf("failed to write to htpasswd file: %v", err)
		}
	}

	return nil
}
