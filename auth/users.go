package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// User represents a user account
type User struct {
	Username  string    `json:"username"`
	Password  string    `json:"password"` // bcrypt hash
	Role      string    `json:"role"`     // admin, developer, readonly, custom
	Email     string    `json:"email,omitempty"`
	FullName  string    `json:"full_name,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// UserStore manages user accounts
type UserStore struct {
	filePath string
	users    map[string]*User // username -> User
	mu       sync.RWMutex
}

// NewUserStore creates a new user store
func NewUserStore(filePath string) (*UserStore, error) {
	store := &UserStore{
		filePath: filePath,
		users:    make(map[string]*User),
	}

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		fmt.Printf("User file not found at %s, creating with default admin user\n", filePath)

		// Create directory if it doesn't exist
		dir := filePath[:len(filePath)-len("/users.json")]
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create auth directory: %v", err)
		}

		// Create default admin user
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("failed to hash default admin password: %v", err)
		}

		now := time.Now()
		store.users["admin"] = &User{
			Username:  "admin",
			Password:  string(hashedPassword),
			Role:      "admin",
			Email:     "admin@localhost",
			FullName:  "Administrator",
			CreatedAt: now,
			UpdatedAt: now,
		}

		// Save the file with default admin user
		if err := store.save(); err != nil {
			return nil, fmt.Errorf("failed to create default user file: %v", err)
		}

		fmt.Printf("✓ Default admin user created (username: admin, password: admin)\n")
		fmt.Printf("⚠ IMPORTANT: Please change the default admin password immediately!\n")
	} else if err != nil {
		return nil, fmt.Errorf("failed to check user file: %v", err)
	} else {
		// File exists, load it
		if err := store.load(); err != nil {
			return nil, err
		}
	}

	return store, nil
}

// load reads users from file
func (s *UserStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return fmt.Errorf("failed to read user file: %v", err)
	}

	var users []*User
	if err := json.Unmarshal(data, &users); err != nil {
		return fmt.Errorf("failed to parse user file: %v", err)
	}

	s.users = make(map[string]*User)
	for _, user := range users {
		s.users[user.Username] = user
	}

	return nil
}

// save writes users to file
func (s *UserStore) save() error {
	users := make([]*User, 0, len(s.users))
	for _, user := range s.users {
		users = append(users, user)
	}

	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal users: %v", err)
	}

	if err := os.WriteFile(s.filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write user file: %v", err)
	}

	return nil
}

// Authenticate verifies username and password
func (s *UserStore) Authenticate(username, password string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[username]
	if !exists {
		return false
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	return err == nil
}

// GetUser returns a user by username
func (s *UserStore) GetUser(username string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[username]
	if !exists {
		return nil, fmt.Errorf("user not found")
	}

	return user, nil
}

// GetUserRole returns the role of a user
func (s *UserStore) GetUserRole(username string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[username]
	if !exists {
		return ""
	}

	return user.Role
}

// ListUsers returns all usernames
func (s *UserStore) ListUsers() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	usernames := make([]string, 0, len(s.users))
	for username := range s.users {
		usernames = append(usernames, username)
	}
	return usernames
}

// ListUsersWithDetails returns all users with their details
func (s *UserStore) ListUsersWithDetails() []*User {
	s.mu.RLock()
	defer s.mu.RUnlock()

	users := make([]*User, 0, len(s.users))
	for _, user := range s.users {
		users = append(users, user)
	}
	return users
}

// UserExists checks if a username exists
func (s *UserStore) UserExists(username string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, exists := s.users[username]
	return exists
}

// AddUser adds a new user
func (s *UserStore) AddUser(username, password, role, email, fullName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[username]; exists {
		return fmt.Errorf("user already exists")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}

	now := time.Now()
	s.users[username] = &User{
		Username:  username,
		Password:  string(hashedPassword),
		Role:      role,
		Email:     email,
		FullName:  fullName,
		CreatedAt: now,
		UpdatedAt: now,
	}

	return s.save()
}

// UpdatePassword updates a user's password
func (s *UserStore) UpdatePassword(username, newPassword string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, exists := s.users[username]
	if !exists {
		return fmt.Errorf("user does not exist")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}

	user.Password = string(hashedPassword)
	user.UpdatedAt = time.Now()

	return s.save()
}

// UpdateUser updates a user's details
func (s *UserStore) UpdateUser(username string, role, email, fullName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, exists := s.users[username]
	if !exists {
		return fmt.Errorf("user does not exist")
	}

	if role != "" {
		user.Role = role
	}
	if email != "" {
		user.Email = email
	}
	if fullName != "" {
		user.FullName = fullName
	}
	user.UpdatedAt = time.Now()

	return s.save()
}

// DeleteUser removes a user
func (s *UserStore) DeleteUser(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[username]; !exists {
		return fmt.Errorf("user does not exist")
	}

	delete(s.users, username)
	return s.save()
}
