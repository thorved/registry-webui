package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	RegistryURL      string
	HtpasswdPath     string
	WebUIPort        string
	SessionSecret    string
	RegistryUsername string
	RegistryPassword string
}

func Load() *Config {
	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	cfg := &Config{
		RegistryURL:      getEnv("REGISTRY_URL", "http://localhost:5000"),
		HtpasswdPath:     getEnv("REGISTRY_AUTH_HTPASSWD_PATH", "/auth/registry.password"),
		WebUIPort:        getEnv("WEB_UI_PORT", "8080"),
		SessionSecret:    getEnv("SESSION_SECRET", "default-secret-change-me"),
		RegistryUsername: getEnv("REGISTRY_USERNAME", ""),
		RegistryPassword: getEnv("REGISTRY_PASSWORD", ""),
	}

	return cfg
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
