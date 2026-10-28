package bypass

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/MohammadAliMehri/ReconSaas/internal/engine"
	"github.com/MohammadAliMehri/ReconSaas/internal/model"
	"github.com/MohammadAliMehri/ReconSaas/internal/scope"
)

// Module runs non-destructive 403 Forbidden diagnostics on blocked assets.
type Module struct {
	pathPayloads   []string
	headerPayloads []map[string]string
}

// New creates a new bypass module instance.
func New() *Module {
	return &Module{
		pathPayloads: []string{
			";", "..;", "%2e/", "/.", "%20",
		},
		headerPayloads: []map[string]string{
			{"X-Forwarded-For": "127.0.0.1"},
			{"X-Original-URL": "/"},
			{"X-Rewrite-URL": "/"},
			{"X-Custom-IP-Authorization": "127.0.0.1"},
			{"Referer": "127.0.0.1"},
		},
	}
}

func (m *Module) ID() string          { return "bypass" }
func (m *Module) Phase() model.Mode   { return model.ModeActive }
func (m *Module) Description() string { return "403 Forbidden Diagnostic & Boundary Testing" }

type bypassFinding struct {
	OriginalPath string `json:"original_path"`
	BypassURL    string `json:"bypass_url"`
	Technique    string `json:"technique"`
	Status       int    `json:"status"`
}

func (m *Module) Run(ctx context.Context, req engine.Request, emit func(model.Finding) error) (*model.ModuleResult, error) {
	domain := scope.CanonicalizeDomain(req.Target)
	var findings []model.Finding

	baseURL := req.Target
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = fmt.Sprintf("https://%s", domain)
	}
	baseURL = strings.TrimSuffix(baseURL, "/")

	// Candidate 403 paths to diagnose
	candidatePaths := []string{"/admin", "/internal", "/api/admin", "/actuator/env"}

	var bypassesFound []bypassFinding

	for _, basePath := range candidatePaths {
		if ctx.Err() != nil {
			break
		}

		targetURL := baseURL + basePath
		resp, err := req.Client.Get(ctx, targetURL, nil)
		if err != nil || resp.StatusCode != 403 {
			// Only diagnose endpoints that return 403 Forbidden
			continue
		}

		// 1. Path Normalization Tricks
		for _, payload := range m.pathPayloads {
			bypassURL := fmt.Sprintf("%s/%s%s", baseURL, strings.TrimPrefix(basePath, "/"), payload)
			if bResp, err := req.Client.Get(ctx, bypassURL, nil); err == nil {
				if bResp.StatusCode == 200 || bResp.StatusCode == 301 || bResp.StatusCode == 302 {
					bf := bypassFinding{
						OriginalPath: basePath,
						BypassURL:    bypassURL,
						Technique:    fmt.Sprintf("path normalization (%s)", payload),
						Status:       bResp.StatusCode,
					}
					bypassesFound = append(bypassesFound, bf)
					f := model.Finding{
						ID:        fmt.Sprintf("bypass-path-%s-%s", strings.ReplaceAll(basePath, "/", "_"), domain),
						Module:    m.ID(),
						Target:    domain,
						Title:     fmt.Sprintf("403 Discrepancy on %s via Path Normalization", basePath),
						Detail:    fmt.Sprintf("Path %s returned %d when appended with %q.", bypassURL, bResp.StatusCode, payload),
						Severity:  model.SeverityMedium,
						Timestamp: time.Now().UTC(),
						Evidence: []model.Evidence{
							{Type: "bypass_technique", Source: bypassURL, Data: bResp.StatusCode},
						},
					}
					findings = append(findings, f)
					_ = emit(f)
					break
				}
			}
		}

		// 2. Header Spoofing Tricks
		for _, h := range m.headerPayloads {
			if bResp, err := req.Client.Get(ctx, targetURL, h); err == nil {
				if bResp.StatusCode == 200 || bResp.StatusCode == 301 || bResp.StatusCode == 302 {
					var hDesc []string
					for k, v := range h {
						hDesc = append(hDesc, fmt.Sprintf("%s: %s", k, v))
					}
					bf := bypassFinding{
						OriginalPath: basePath,
						BypassURL:    targetURL,
						Technique:    fmt.Sprintf("header spoof (%s)", strings.Join(hDesc, ", ")),
						Status:       bResp.StatusCode,
					}
					bypassesFound = append(bypassesFound, bf)
					f := model.Finding{
						ID:        fmt.Sprintf("bypass-hdr-%s-%s", strings.ReplaceAll(basePath, "/", "_"), domain),
						Module:    m.ID(),
						Target:    domain,
						Title:     fmt.Sprintf("403 Discrepancy on %s via Header Spoofing", basePath),
						Detail:    fmt.Sprintf("Request returned %d with headers: %s.", bResp.StatusCode, strings.Join(hDesc, ", ")),
						Severity:  model.SeverityMedium,
						Timestamp: time.Now().UTC(),
						Evidence: []model.Evidence{
							{Type: "bypass_technique", Source: targetURL, Data: h},
						},
					}
					findings = append(findings, f)
					_ = emit(f)
					break
				}
			}
		}
	}

	data := map[string]interface{}{
		"bypasses_found": bypassesFound,
		"total_found":    len(bypassesFound),
	}

	return &model.ModuleResult{
		Module:    m.ID(),
		Target:    domain,
		Findings:  findings,
		Data:      data,
		Timestamp: time.Now().UTC(),
	}, nil
}

