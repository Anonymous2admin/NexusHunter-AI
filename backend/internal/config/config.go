package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

var (
	ErrMissingDatabaseURL = errors.New("DATABASE_URL is required in production environment")
	ErrInvalidHTTPPort    = errors.New("HTTP_PORT must be a valid positive integer between 1 and 65535")
	ErrInvalidLogLevel    = errors.New("LOG_LEVEL must be one of: debug, info, warn, error")
)

// Config encapsulates runtime operational settings for NexusHunter-AI.
type Config struct {
	AppEnv       string `json:"app_env"`
	HTTPPort     int    `json:"http_port"`
	DatabaseURL  string `json:"database_url"`
	RedisURL     string `json:"redis_url"`
	LogLevel     string `json:"log_level"`
	ServiceName  string `json:"service_name"`
	Version      string `json:"version"`
	AIServiceURL string `json:"ai_service_url"`
}

// Load extracts and validates application configuration from environment variables.
func Load() (*Config, error) {
	env := getEnv("APP_ENV", "development")
	portStr := getEnv("HTTP_PORT", "8080")
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("%w: received '%s'", ErrInvalidHTTPPort, portStr)
	}

	dbURL := getEnv("DATABASE_URL", "")
	redisURL := getEnv("REDIS_URL", "redis://localhost:6379/0")
	aiURL := getEnv("AI_SERVICE_URL", "http://localhost:8001")
	logLevel := strings.ToLower(getEnv("LOG_LEVEL", "info"))

	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLevels[logLevel] {
		return nil, fmt.Errorf("%w: received '%s'", ErrInvalidLogLevel, logLevel)
	}

	// In production, database URL is strictly mandatory
	if env == "production" && dbURL == "" {
		return nil, ErrMissingDatabaseURL
	}

	cfg := &Config{
		AppEnv:       env,
		HTTPPort:     port,
		DatabaseURL:  dbURL,
		RedisURL:     redisURL,
		LogLevel:     logLevel,
		ServiceName:  "nexushunter-api",
		Version:      "0.1.0-alpha",
		AIServiceURL: aiURL,
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	return val
}
