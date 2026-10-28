package config

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/MohammadAliMehri/ReconSaas/internal/model"
	"github.com/MohammadAliMehri/ReconSaas/internal/scope"
)

var (
	ErrInvalidConfig = errors.New("invalid configuration")
)

// ScopeConfig maps directly to scope.Policy in YAML.
type ScopeConfig struct {
	AllowDomains        []string `yaml:"allow_domains"`
	AllowCIDRs          []string `yaml:"allow_cidrs"`
	DenyPrivateNetworks bool     `yaml:"deny_private_networks"`
	FollowRedirects     bool     `yaml:"follow_redirects"`
}

// LimitsConfig configures concurrency, request rates, timeouts, and byte limits.
type LimitsConfig struct {
	GlobalConcurrency  int   `yaml:"global_concurrency"`
	PerHostConcurrency int   `yaml:"per_host_concurrency"`
	RequestsPerSecond  int   `yaml:"requests_per_second"`
	TimeoutSeconds     int   `yaml:"timeout_seconds"`
	MaxResponseBytes   int64 `yaml:"max_response_bytes"`
	MaxRedirects       int   `yaml:"max_redirects"`
}

// ModulesConfig lists enabled reconnaissance modules.
type ModulesConfig struct {
	Enabled []string `yaml:"enabled"`
}

// OutputConfig configures output directory and redaction.
type OutputConfig struct {
	Dir           string `yaml:"dir"`
	RedactSecrets bool   `yaml:"redact_secrets"`
}

// AIConfig configures optional OpenAI-compatible offline/local LLM integration.
type AIConfig struct {
	Enabled bool   `yaml:"enabled"`
	BaseURL string `yaml:"base_url"`
	Model   string `yaml:"model"`
	APIKey  string `yaml:"api_key"`
}

// Config represents the complete validated configuration file.
type Config struct {
	Version int           `yaml:"version"`
	Mode    model.Mode    `yaml:"mode"`
	Scope   ScopeConfig   `yaml:"scope"`
	Limits  LimitsConfig  `yaml:"limits"`
	Modules ModulesConfig `yaml:"modules"`
	Output  OutputConfig  `yaml:"output"`
	AI      AIConfig      `yaml:"ai"`
}

// DefaultConfig returns a safe, passive-first configuration baseline.
func DefaultConfig() *Config {
	return &Config{
		Version: 1,
		Mode:    model.ModePassive,
		Scope: ScopeConfig{
			AllowDomains:        []string{},
			AllowCIDRs:          []string{},
			DenyPrivateNetworks: true,
			FollowRedirects:     false,
		},
		Limits: LimitsConfig{
			GlobalConcurrency:  10,
			PerHostConcurrency: 2,
			RequestsPerSecond:  2,
			TimeoutSeconds:     15,
			MaxResponseBytes:   2 * 1024 * 1024, // 2MB
			MaxRedirects:       3,
		},
		Modules: ModulesConfig{
			Enabled: []string{
				"dns", "certs", "wayback", "js", "tech", "headers",
				"dirs", "endpoints", "bypass", "rank", "report",
			},
		},
		Output: OutputConfig{
			Dir:           "./recon-output",
			RedactSecrets: true,
		},
		AI: AIConfig{
			Enabled: false,
			BaseURL: "http://127.0.0.1:1234/v1",
			Model:   "",
		},
	}
}

// Load loads and parses a YAML configuration file from path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %q: %w", path, err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config YAML: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate checks configuration invariants.
func (c *Config) Validate() error {
	if c.Version != 1 {
		return fmt.Errorf("%w: unsupported config version %d (expected 1)", ErrInvalidConfig, c.Version)
	}

	switch c.Mode {
	case model.ModePassive, model.ModeActive, model.ModeHybrid:
		// Valid
	default:
		return fmt.Errorf("%w: unknown mode %q", ErrInvalidConfig, c.Mode)
	}

	if c.Limits.GlobalConcurrency <= 0 {
		return fmt.Errorf("%w: global_concurrency must be > 0", ErrInvalidConfig)
	}
	if c.Limits.TimeoutSeconds <= 0 {
		return fmt.Errorf("%w: timeout_seconds must be > 0", ErrInvalidConfig)
	}
	if c.Limits.MaxResponseBytes <= 0 {
		return fmt.Errorf("%w: max_response_bytes must be > 0", ErrInvalidConfig)
	}

	return nil
}

// ToScopePolicy converts ScopeConfig into an active scope.Policy.
func (c *Config) ToScopePolicy() scope.Policy {
	return scope.Policy{
		AllowDomains:        c.Scope.AllowDomains,
		AllowCIDRStrings:    c.Scope.AllowCIDRs,
		DenyPrivateNetworks: c.Scope.DenyPrivateNetworks,
		FollowRedirects:     c.Scope.FollowRedirects,
	}
}

