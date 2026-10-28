package tech

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/MohammadAliMehri/ReconSaas/internal/engine"
	"github.com/MohammadAliMehri/ReconSaas/internal/fingerprint"
	"github.com/MohammadAliMehri/ReconSaas/internal/model"
	"github.com/MohammadAliMehri/ReconSaas/internal/scope"
)

// Module performs deterministic technology stack fingerprinting.
type Module struct {
	engine *fingerprint.Engine
}

// New creates a new tech module instance.
func New() (*Module, error) {
	eng, err := fingerprint.NewEngine()
	if err != nil {
		return nil, err
	}
	return &Module{engine: eng}, nil
}

func (m *Module) ID() string          { return "tech" }
func (m *Module) Phase() model.Mode   { return model.ModeActive }
func (m *Module) Description() string { return "Technology Stack Fingerprinting (205+ signatures)" }

func (m *Module) Run(ctx context.Context, req engine.Request, emit func(model.Finding) error) (*model.ModuleResult, error) {
	domain := scope.CanonicalizeDomain(req.Target)
	var findings []model.Finding

	targetURL := req.Target
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = fmt.Sprintf("https://%s", domain)
	}

	resp, err := req.Client.Get(ctx, targetURL, nil)
	if err != nil {
		// Fallback to HTTP if HTTPS failed
		if strings.HasPrefix(targetURL, "https://") {
			targetURL = "http://" + strings.TrimPrefix(targetURL, "https://")
			resp, err = req.Client.Get(ctx, targetURL, nil)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to reach target for fingerprinting: %w", err)
	}

	// Prepare data for fingerprint engine
	headers := make(map[string]string)
	for k, v := range resp.Headers {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	var cookieNames []string
	for _, c := range resp.Cookies {
		cookieNames = append(cookieNames, c.Name)
	}

	body := string(resp.Body)

	// Extract <script src="...">
	scriptRe := regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
	var scriptSources []string
	for _, match := range scriptRe.FindAllStringSubmatch(body, -1) {
		if len(match) > 1 {
			scriptSources = append(scriptSources, match[1])
		}
	}

	matches := m.engine.Analyze(headers, cookieNames, body, targetURL, scriptSources)

	var techNames []string
	byCategory := make(map[string][]string)
	for _, match := range matches {
		label := match.Name
		if match.Version != "" {
			label = fmt.Sprintf("%s %s", match.Name, match.Version)
		}
		techNames = append(techNames, label)

		for _, cat := range match.CategoryNames {
			byCategory[cat] = append(byCategory[cat], label)
		}

		f := model.Finding{
			ID:        fmt.Sprintf("tech-%s-%s", strings.ToLower(match.Name), domain),
			Module:    m.ID(),
			Target:    domain,
			Title:     fmt.Sprintf("Technology Identified: %s", label),
			Detail:    fmt.Sprintf("Detected via %s (confidence %d%%)", match.MatchedBy, match.Confidence),
			Severity:  model.SeverityInfo,
			Timestamp: time.Now().UTC(),
			Evidence: []model.Evidence{
				{Type: match.MatchedBy, Source: targetURL, Data: match.MatchedPattern},
			},
		}
		findings = append(findings, f)
		_ = emit(f)
	}

	// Store identified technologies in shared data for reporting and asset ranking
	req.SharedData.Store("technologies", techNames)

	data := map[string]interface{}{
		"technologies": matches,
		"tech_names":   techNames,
		"tech_count":   len(matches),
		"by_category":  byCategory,
	}

	return &model.ModuleResult{
		Module:    m.ID(),
		Target:    domain,
		Findings:  findings,
		Data:      data,
		Timestamp: time.Now().UTC(),
	}, nil
}

