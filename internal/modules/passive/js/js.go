package js

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/MohammadAliMehri/ReconSaas/internal/engine"
	"github.com/MohammadAliMehri/ReconSaas/internal/model"
	"github.com/MohammadAliMehri/ReconSaas/internal/scope"
)

// Module analyzes JavaScript bundles for API endpoints, credentials, routes, and cloud buckets.
type Module struct {
	patterns map[string]*regexp.Regexp
}

// New creates a new js module instance.
func New() *Module {
	return &Module{
		patterns: map[string]*regexp.Regexp{
			"api_endpoint": regexp.MustCompile(`(?i)["'` + "`" + `](/api/[a-zA-Z0-9/_-]+|https?://[a-zA-Z0-9.-]+/api/[a-zA-Z0-9/_-]+)["'` + "`" + `]`),
			"graphql":      regexp.MustCompile(`(?i)["'` + "`" + `](/graphql|/gql|/query)["'` + "`" + `]`),
			"swagger":      regexp.MustCompile(`(?i)["'` + "`" + `](/(?:swagger|openapi|api-docs)[^"'` + "`" + `]*\.?(?:json|yaml)?)["'` + "`" + `]`),
			"aws_key":      regexp.MustCompile(`(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}`),
			"jwt":          regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]+`),
			"s3_bucket":    regexp.MustCompile(`(?i)(?:https?://)?[a-zA-Z0-9.-]*\.s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com|s3://[a-zA-Z0-9][a-zA-Z0-9.-]*`),
			"internal_ip":  regexp.MustCompile(`\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b`),
			"route_path":   regexp.MustCompile(`["'` + "`" + `](/[a-zA-Z0-9/_-]{3,})["'` + "`" + `]\s*[,;\)]`),
		},
	}
}

func (m *Module) ID() string          { return "js" }
func (m *Module) Phase() model.Mode   { return model.ModePassive }
func (m *Module) Description() string { return "JavaScript Bundle Analysis" }

func (m *Module) Run(ctx context.Context, req engine.Request, emit func(model.Finding) error) (*model.ModuleResult, error) {
	domain := scope.CanonicalizeDomain(req.Target)
	var findings []model.Finding

	endpoints := make(map[string]bool)
	routes := make(map[string]bool)
	s3Buckets := make(map[string]bool)
	internalIPs := make(map[string]bool)
	var secrets []map[string]string

	// Inspect JavaScript URLs from Wayback historical archives
	if rawWayback, ok := req.SharedData.Load("wayback_urls"); ok {
		if urlEntries, ok := rawWayback.([]map[string]string); ok {
			for _, entry := range urlEntries {
				u := entry["url"]
				if strings.Contains(strings.ToLower(u), ".js") {
					// Extract endpoints and routes embedded directly in JS URL paths
					endpoints[u] = true
				}
			}
		}
	}

	// Active inspection: fetch landing page and inspect scripts only when in active mode or authorized
	activeAuthorized := false
	if authVal, ok := req.Config["authorized"].(bool); ok && authVal {
		activeAuthorized = true
	}

	if activeAuthorized {
		baseURL := req.Target
		if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
			baseURL = "https://" + baseURL
		}
		if resp, err := req.Client.Get(ctx, baseURL, nil); err == nil && resp.StatusCode == 200 {
			body := string(resp.Body)
			m.analyzeContent(body, baseURL, endpoints, routes, s3Buckets, internalIPs, &secrets)

			// Discover and inspect linked script URLs
			scriptSrcRe := regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+\.js[^"']*)["']`)
			matches := scriptSrcRe.FindAllStringSubmatch(body, -1)
			for _, match := range matches {
				if len(match) > 1 {
					scriptURL := match[1]
					if strings.HasPrefix(scriptURL, "//") {
						scriptURL = "https:" + scriptURL
					} else if strings.HasPrefix(scriptURL, "/") {
						scriptURL = baseURL + scriptURL
					} else if !strings.HasPrefix(scriptURL, "http") {
						scriptURL = baseURL + "/" + scriptURL
					}

					// Verify scriptURL is in scope before fetching
					if err := req.Scope.ValidateURL(scriptURL); err == nil {
						if jsResp, err := req.Client.Get(ctx, scriptURL, nil); err == nil && jsResp.StatusCode == 200 {
							m.analyzeContent(string(jsResp.Body), scriptURL, endpoints, routes, s3Buckets, internalIPs, &secrets)
						}
					}
				}
			}
		}
	}

	var endpointList []string
	for ep := range endpoints {
		endpointList = append(endpointList, ep)
	}
	sort.Strings(endpointList)

	var routeList []string
	for r := range routes {
		routeList = append(routeList, r)
	}
	sort.Strings(routeList)

	var bucketList []string
	for b := range s3Buckets {
		bucketList = append(bucketList, b)
	}
	sort.Strings(bucketList)

	var ipList []string
	for ip := range internalIPs {
		ipList = append(ipList, ip)
	}
	sort.Strings(ipList)

	// Save endpoints and routes in shared data
	req.SharedData.Store("js_endpoints", endpointList)

	if len(endpointList) > 0 {
		f := model.Finding{
			ID:        fmt.Sprintf("js-endpoints-%s", domain),
			Module:    m.ID(),
			Target:    domain,
			Title:     fmt.Sprintf("Discovered API Endpoints in JavaScript (%d)", len(endpointList)),
			Detail:    fmt.Sprintf("Found %d endpoints across inspected scripts.", len(endpointList)),
			Severity:  model.SeverityInfo,
			Timestamp: time.Now().UTC(),
		}
		findings = append(findings, f)
		_ = emit(f)
	}

	if len(secrets) > 0 {
		f := model.Finding{
			ID:        fmt.Sprintf("js-secrets-%s", domain),
			Module:    m.ID(),
			Target:    domain,
			Title:     fmt.Sprintf("Candidate Secrets in JavaScript (%d)", len(secrets)),
			Detail:    fmt.Sprintf("Extracted %d masked secret tokens.", len(secrets)),
			Severity:  model.SeverityHigh,
			Timestamp: time.Now().UTC(),
		}
		findings = append(findings, f)
		_ = emit(f)
	}

	if len(bucketList) > 0 {
		f := model.Finding{
			ID:        fmt.Sprintf("js-buckets-%s", domain),
			Module:    m.ID(),
			Target:    domain,
			Title:     fmt.Sprintf("Amazon S3 Buckets Referenced (%d)", len(bucketList)),
			Detail:    strings.Join(bucketList, ", "),
			Severity:  model.SeverityLow,
			Timestamp: time.Now().UTC(),
		}
		findings = append(findings, f)
		_ = emit(f)
	}

	data := map[string]interface{}{
		"endpoints":    endpointList,
		"routes":       routeList,
		"secrets":      secrets,
		"s3_buckets":   bucketList,
		"internal_ips": ipList,
	}

	return &model.ModuleResult{
		Module:    m.ID(),
		Target:    domain,
		Findings:  findings,
		Data:      data,
		Timestamp: time.Now().UTC(),
	}, nil
}

func (m *Module) analyzeContent(
	content string,
	source string,
	endpoints map[string]bool,
	routes map[string]bool,
	s3Buckets map[string]bool,
	internalIPs map[string]bool,
	secrets *[]map[string]string,
) {
	// Endpoints
	for _, match := range m.patterns["api_endpoint"].FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			endpoints[match[1]] = true
		}
	}
	for _, match := range m.patterns["graphql"].FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			endpoints[match[1]] = true
		}
	}
	for _, match := range m.patterns["swagger"].FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			endpoints[match[1]] = true
		}
	}

	// Routes
	for _, match := range m.patterns["route_path"].FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			routes[match[1]] = true
		}
	}

	// S3 Buckets
	for _, match := range m.patterns["s3_bucket"].FindAllString(content, -1) {
		s3Buckets[match] = true
	}

	// Internal IPs
	for _, match := range m.patterns["internal_ip"].FindAllString(content, -1) {
		internalIPs[match] = true
	}

	// AWS Keys (masked)
	for _, key := range m.patterns["aws_key"].FindAllString(content, -1) {
		masked := key[:4] + "****************"
		*secrets = append(*secrets, map[string]string{
			"type":   "AWS Access Key ID",
			"value":  masked,
			"source": source,
		})
	}

	// JWT Tokens (masked)
	for _, jwt := range m.patterns["jwt"].FindAllString(content, -1) {
		masked := jwt[:12] + "...[REDACTED]"
		*secrets = append(*secrets, map[string]string{
			"type":   "JSON Web Token",
			"value":  masked,
			"source": source,
		})
	}
}
