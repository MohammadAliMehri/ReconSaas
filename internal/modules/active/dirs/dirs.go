package dirs

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/MohammadAliMehri/ReconSaas/internal/engine"
	"github.com/MohammadAliMehri/ReconSaas/internal/model"
	"github.com/MohammadAliMehri/ReconSaas/internal/scope"
)

// Module performs bounded dictionary-based directory and backup discovery.
type Module struct {
	wordlist []string
}

// New creates a new dirs module instance.
func New() *Module {
	return &Module{
		wordlist: []string{
			// Admin / Auth
			"admin", "administrator", "login", "auth", "cpanel", "dashboard", "console",
			// API
			"api", "api/v1", "api/v2", "graphql", "swagger", "docs", "openapi.json",
			// Sensitive files
			".env", ".git/HEAD", ".git/config", "robots.txt", "sitemap.xml",
			"wp-config.php.bak", "database.sql", "backup.zip", "dump.sql",
			// Cloud / Dev
			".aws", "actuator/health", "actuator/env", "debug", "server-status",
		},
	}
}

func (m *Module) ID() string          { return "dirs" }
func (m *Module) Phase() model.Mode   { return model.ModeActive }
func (m *Module) Description() string { return "Directory & Sensitive File Bruteforce" }

type dirFinding struct {
	Path       string `json:"path"`
	StatusCode int    `json:"status"`
	Title      string `json:"title,omitempty"`
}

func (m *Module) Run(ctx context.Context, req engine.Request, emit func(model.Finding) error) (*model.ModuleResult, error) {
	domain := scope.CanonicalizeDomain(req.Target)
	var findings []model.Finding

	baseURL := req.Target
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = fmt.Sprintf("https://%s", domain)
	}
	baseURL = strings.TrimSuffix(baseURL, "/")

	// Soft-404 baseline check
	baselineURL := fmt.Sprintf("%s/recon-nonexistent-path-%d", baseURL, time.Now().UnixNano())
	var baselineCode int
	var baselineLen int
	if resp, err := req.Client.Get(ctx, baselineURL, nil); err == nil {
		baselineCode = resp.StatusCode
		baselineLen = len(resp.Body)
	}

	var discovered []dirFinding

	for _, path := range m.wordlist {
		if ctx.Err() != nil {
			break
		}

		targetURL := fmt.Sprintf("%s/%s", baseURL, path)
		resp, err := req.Client.Get(ctx, targetURL, nil)
		if err != nil {
			continue
		}

		// Filter out 404s and soft-404s
		if resp.StatusCode == 404 {
			continue
		}
		if baselineCode != 0 && resp.StatusCode == baselineCode && len(resp.Body) == baselineLen {
			continue
		}

		if resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 403 {
			df := dirFinding{
				Path:       "/" + path,
				StatusCode: resp.StatusCode,
			}
			discovered = append(discovered, df)

			sev := model.SeverityInfo
			if strings.HasPrefix(path, ".env") || strings.HasPrefix(path, ".git") || strings.Contains(path, "backup") || strings.Contains(path, ".sql") {
				sev = model.SeverityHigh
			} else if resp.StatusCode == 200 && (strings.Contains(path, "admin") || strings.Contains(path, "actuator")) {
				sev = model.SeverityMedium
			}

			f := model.Finding{
				ID:        fmt.Sprintf("dir-%s-%s", strings.ReplaceAll(path, "/", "_"), domain),
				Module:    m.ID(),
				Target:    domain,
				Title:     fmt.Sprintf("Discovered Path: /%s (HTTP %d)", path, resp.StatusCode),
				Detail:    fmt.Sprintf("Accessible path found at %s with HTTP status %d.", targetURL, resp.StatusCode),
				Severity:  sev,
				Timestamp: time.Now().UTC(),
				Evidence: []model.Evidence{
					{Type: "http_status", Source: targetURL, Data: resp.StatusCode},
				},
			}
			findings = append(findings, f)
			_ = emit(f)
		}
	}

	// Store discovered paths in shared data
	req.SharedData.Store("dir_paths", discovered)

	data := map[string]interface{}{
		"found":       discovered,
		"total_found": len(discovered),
		"tested":      len(m.wordlist),
	}

	return &model.ModuleResult{
		Module:    m.ID(),
		Target:    domain,
		Findings:  findings,
		Data:      data,
		Timestamp: time.Now().UTC(),
	}, nil
}

