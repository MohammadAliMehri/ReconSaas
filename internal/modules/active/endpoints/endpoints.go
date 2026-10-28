package endpoints

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/MohammadAliMehri/ReconSaas/internal/engine"
	"github.com/MohammadAliMehri/ReconSaas/internal/model"
	"github.com/MohammadAliMehri/ReconSaas/internal/scope"
)

// Module probes for standard API documentation, OpenAPI specs, GraphQL endpoints, and diagnostic paths.
type Module struct {
	endpoints []probeTarget
}

type probeTarget struct {
	Path  string
	Label string
}

// New creates a new endpoints module instance.
func New() *Module {
	return &Module{
		endpoints: []probeTarget{
			{"/swagger", "Swagger UI"},
			{"/swagger-ui.html", "Swagger UI"},
			{"/api-docs", "API Documentation"},
			{"/openapi.json", "OpenAPI Specification"},
			{"/swagger.json", "Swagger Specification"},
			{"/redoc", "ReDoc"},
			{"/graphql", "GraphQL Endpoint"},
			{"/gql", "GraphQL Endpoint"},
			{"/graphiql", "GraphiQL Interface"},
			{"/robots.txt", "Robots File"},
			{"/sitemap.xml", "Sitemap File"},
			{"/.well-known/security.txt", "Security Contact"},
			{"/actuator/health", "Spring Actuator Health"},
			{"/actuator/env", "Spring Actuator Environment"},
			{"/healthz", "Kubernetes Healthz"},
		},
	}
}

func (m *Module) ID() string          { return "endpoints" }
func (m *Module) Phase() model.Mode   { return model.ModeActive }
func (m *Module) Description() string { return "API Documentation & Standard Endpoint Probing" }

type endpointResult struct {
	Path   string `json:"path"`
	Label  string `json:"label"`
	Status int    `json:"status"`
}

func (m *Module) Run(ctx context.Context, req engine.Request, emit func(model.Finding) error) (*model.ModuleResult, error) {
	domain := scope.CanonicalizeDomain(req.Target)
	var findings []model.Finding

	baseURL := req.Target
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = fmt.Sprintf("https://%s", domain)
	}
	baseURL = strings.TrimSuffix(baseURL, "/")

	var discovered []endpointResult

	for _, ep := range m.endpoints {
		if ctx.Err() != nil {
			break
		}

		targetURL := baseURL + ep.Path
		resp, err := req.Client.Get(ctx, targetURL, nil)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302 {
			res := endpointResult{
				Path:   ep.Path,
				Label:  ep.Label,
				Status: resp.StatusCode,
			}
			discovered = append(discovered, res)

			sev := model.SeverityInfo
			if strings.Contains(ep.Path, "actuator/env") {
				sev = model.SeverityHigh
			} else if strings.Contains(ep.Path, "swagger") || strings.Contains(ep.Path, "graphql") {
				sev = model.SeverityMedium
			}

			f := model.Finding{
				ID:        fmt.Sprintf("endpoint-%s-%s", strings.ReplaceAll(ep.Path, "/", "_"), domain),
				Module:    m.ID(),
				Target:    domain,
				Title:     fmt.Sprintf("Discovered %s: %s (HTTP %d)", ep.Label, ep.Path, resp.StatusCode),
				Detail:    fmt.Sprintf("Found active endpoint %s responding with status %d.", targetURL, resp.StatusCode),
				Severity:  sev,
				Timestamp: time.Now().UTC(),
				Evidence: []model.Evidence{
					{Type: "endpoint_probe", Source: targetURL, Data: resp.StatusCode},
				},
			}
			findings = append(findings, f)
			_ = emit(f)
		}
	}

	// Store discovered endpoints in shared data
	req.SharedData.Store("probed_endpoints", discovered)

	data := map[string]interface{}{
		"discovered": discovered,
		"total":      len(discovered),
	}

	return &model.ModuleResult{
		Module:    m.ID(),
		Target:    domain,
		Findings:  findings,
		Data:      data,
		Timestamp: time.Now().UTC(),
	}, nil
}

