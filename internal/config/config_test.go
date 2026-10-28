package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/MohammadAliMehri/ReconSaas/internal/model"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("DefaultConfig failed validation: %v", err)
	}

	if cfg.Mode != model.ModePassive {
		t.Errorf("expected default mode to be passive, got %s", cfg.Mode)
	}
	if !cfg.Scope.DenyPrivateNetworks {
		t.Errorf("expected DenyPrivateNetworks to be true by default")
	}
}

func TestLoad_ValidYaml(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "recon-config-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	yamlContent := `
version: 1
mode: hybrid
scope:
  allow_domains: ["example.com"]
  deny_private_networks: true
limits:
  global_concurrency: 20
  timeout_seconds: 30
  max_response_bytes: 1048576
`
	configPath := filepath.Join(tempDir, "recon.yaml")
	if err := os.WriteFile(configPath, []byte(yamlContent), 0600); err != nil {
		t.Fatalf("failed to write test yaml: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Mode != model.ModeHybrid {
		t.Errorf("expected mode hybrid, got %s", cfg.Mode)
	}
	if cfg.Limits.GlobalConcurrency != 20 {
		t.Errorf("expected global_concurrency 20, got %d", cfg.Limits.GlobalConcurrency)
	}
}

func TestValidate_InvalidInputs(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Version = 2 // unsupported
	if err := cfg.Validate(); err == nil {
		t.Errorf("expected error for version 2, got nil")
	}

	cfg = DefaultConfig()
	cfg.Mode = "invalid_mode"
	if err := cfg.Validate(); err == nil {
		t.Errorf("expected error for invalid mode, got nil")
	}

	cfg = DefaultConfig()
	cfg.Limits.GlobalConcurrency = 0
	if err := cfg.Validate(); err == nil {
		t.Errorf("expected error for 0 concurrency, got nil")
	}
}

