package rank

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/MohammadAliMehri/ReconSaas/internal/engine"
	"github.com/MohammadAliMehri/ReconSaas/internal/model"
	"github.com/MohammadAliMehri/ReconSaas/internal/scope"
)

// Module scores discovered assets 0–5 on exploitability using bug bounty money-path methodology.
type Module struct{}

// New creates a new rank module instance.
func New() *Module {
	return &Module{}
}

func (m *Module) ID() string          { return "rank" }
func (m *Module) Phase() model.Mode   { return model.ModePassive } // Runs in analysis phase
func (m *Module) Description() string { return "Asset Exploitability Scoring (0–5 scale)" }

type criteriaRule struct {
	Weight   float64
	Keywords []string
}

var criteria = map[string]criteriaRule{
	"auth_surface": {
		Weight:   1.0,
		Keywords: []string{"login", "signin", "auth", "oauth", "sso", "token", "session", "jwt", "api-key"},
	},
	"multi_tenant": {
		Weight:   1.0,
		Keywords: []string{"org", "tenant", "account", "team", "workspace", "org_id", "account_id"},
	},
	"money_pii": {
		Weight: 1.0,
		Keywords: []string{
			"payment", "billing", "invoice", "checkout", "order", "export",
			"kyc", "profile", "settings", "user", "email", "phone", "address", "ssn",
		},
	},
	"stale_vibes": {
		Weight: 1.0,
		Keywords: []string{
			"old", "legacy", "v1", "beta", "test", "dev", "staging", "debug",
			"backup", ".bak", "php", "asp", "cgi",
		},
	},
	"low_traffic": {
		Weight: 1.0,
		Keywords: []string{
			"admin", "internal", "api", "graphql", "swagger", "actuator",
			"jenkins", "grafana", "kibana", "prometheus",
		},
	},
}

// ScoredAsset represents a ranked asset with its composite score and matching criteria.
type ScoredAsset struct {
	Path     string   `json:"path"`
	Score    float64  `json:"score"`
	Matches  []string `json:"matches"`
	Priority string   `json:"priority"` // Critical, High, Medium, Low
}

func (m *Module) Run(ctx context.Context, req engine.Request, emit func(model.Finding) error) (*model.ModuleResult, error) {
	domain := scope.CanonicalizeDomain(req.Target)
	var findings []model.Finding

	allPaths := make(map[string]bool)

	// Collect paths from shared data
	if rawDirs, ok := req.SharedData.Load("dir_paths"); ok {
		if list, ok := rawDirs.([]struct {
			Path       string `json:"path"`
			StatusCode int    `json:"status"`
			Title      string `json:"title,omitempty"`
		}); ok {
			for _, item := range list {
				allPaths[item.Path] = true
			}
		}
	}

	if rawEndpoints, ok := req.SharedData.Load("probed_endpoints"); ok {
		if list, ok := rawEndpoints.([]struct {
			Path   string `json:"path"`
			Label  string `json:"label"`
			Status int    `json:"status"`
		}); ok {
			for _, item := range list {
				allPaths[item.Path] = true
			}
		}
	}

	if rawWayback, ok := req.SharedData.Load("wayback_paths"); ok {
		if list, ok := rawWayback.([]string); ok {
			for _, p := range list {
				allPaths[p] = true
			}
		}
	}

	if rawJSEndpoints, ok := req.SharedData.Load("js_endpoints"); ok {
		if list, ok := rawJSEndpoints.([]string); ok {
			for _, p := range list {
				allPaths[p] = true
			}
		}
	}

	if rawSubs, ok := req.SharedData.Load("subdomains"); ok {
		if list, ok := rawSubs.([]string); ok {
			for _, s := range list {
				allPaths["[subdomain] "+s] = true
			}
		}
	}

	var scoredAssets []ScoredAsset
	for path := range allPaths {
		score, matches := scorePath(path)
		if score > 0 {
			priority := "Low"
			if score >= 4.0 {
				priority = "Critical"
			} else if score >= 3.0 {
				priority = "High"
			} else if score >= 2.0 {
				priority = "Medium"
			}

			scoredAssets = append(scoredAssets, ScoredAsset{
				Path:     path,
				Score:    score,
				Matches:  matches,
				Priority: priority,
			})
		}
	}

	sort.Slice(scoredAssets, func(i, j int) bool {
		return scoredAssets[i].Score > scoredAssets[j].Score
	})

	topTargets := scoredAssets
	if len(topTargets) > 20 {
		topTargets = topTargets[:20]
	}

	// Store ranked assets in shared data for report generation
	req.SharedData.Store("ranked_assets", topTargets)

	if len(topTargets) > 0 {
		top1 := topTargets[0]
		f := model.Finding{
			ID:        fmt.Sprintf("rank-top-%s", domain),
			Module:    m.ID(),
			Target:    domain,
			Title:     fmt.Sprintf("Top Target Identified: %s (Score: %.1f/5)", top1.Path, top1.Score),
			Detail:    fmt.Sprintf("Highest exploitability priority asset. Matched: %s", strings.Join(top1.Matches, ", ")),
			Severity:  model.SeverityInfo,
			Timestamp: time.Now().UTC(),
		}
		findings = append(findings, f)
		_ = emit(f)
	}

	data := map[string]interface{}{
		"top_targets": topTargets,
		"total_ranked": len(scoredAssets),
	}

	return &model.ModuleResult{
		Module:    m.ID(),
		Target:    domain,
		Findings:  findings,
		Data:      data,
		Timestamp: time.Now().UTC(),
	}, nil
}

func scorePath(path string) (float64, []string) {
	pathLower := strings.ToLower(path)
	var matches []string
	score := 0.0

	for critName, rule := range criteria {
		matched := false
		for _, kw := range rule.Keywords {
			if strings.Contains(pathLower, kw) {
				matched = true
				matches = append(matches, fmt.Sprintf("%s:%s", critName, kw))
				break
			}
		}
		if matched {
			score += rule.Weight
		}
	}

	if score > 5.0 {
		score = 5.0
	}
	return score, matches
}

