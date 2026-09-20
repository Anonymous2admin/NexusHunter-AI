package config

import (
	"os"
	"testing"
)

func TestConfig_LoadDefaults(t *testing.T) {
	os.Unsetenv("APP_ENV")
	os.Unsetenv("HTTP_PORT")
	os.Unsetenv("DATABASE_URL")
	os.Unsetenv("LOG_LEVEL")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected successful config load with defaults, got: %v", err)
	}

	if cfg.HTTPPort != 8080 {
		t.Errorf("expected default HTTP port 8080, got %d", cfg.HTTPPort)
	}
	if cfg.AppEnv != "development" {
		t.Errorf("expected default AppEnv 'development', got '%s'", cfg.AppEnv)
	}
}

func TestConfig_ProductionRequiresDatabaseURL(t *testing.T) {
	os.Setenv("APP_ENV", "production")
	os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("APP_ENV")

	_, err := Load()
	if err == nil {
		t.Fatalf("expected error when DATABASE_URL is missing in production")
	}
}

func TestConfig_InvalidPort(t *testing.T) {
	os.Setenv("HTTP_PORT", "999999")
	defer os.Unsetenv("HTTP_PORT")

	_, err := Load()
	if err == nil {
		t.Fatalf("expected error on invalid port 999999")
	}
}
