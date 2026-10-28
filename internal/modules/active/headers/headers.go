package headers

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/MohammadAliMehri/ReconSaas/internal/engine"
	"github.com/MohammadAliMehri/ReconSaas/internal/model"
	"github.com/MohammadAliMehri/ReconSaas/internal/scope"
)

// Module analyzes security headers, CORS posture, and cookie flags.
type Module struct{}

// New creates a new headers module instance.
func New() *Module {
	return &Module{}
}

func (m *Module) ID() string          { return "headers" }
func (m *Module) Phase() model.Mode   { return model.ModeActive }
func (m *Module) Description() string { return "Security Header & CORS Analysis" }

type secHeaderCheck struct {
	PresentDesc string
	MissingDesc string
	Severity    model.Severity
}

var standardChecks = map[string]secHeaderCheck{
	"Strict-Transport-Security": {
		PresentDesc: "HSTS enabled",
		MissingDesc: "Missing HSTS allows SSL-stripping downgrade attacks",
		Severity:    model.SeverityMedium,
	},
	"Content-Security-Policy": {
		PresentDesc: "CSP enabled",
		MissingDesc: "Missing CSP increases exposure to Cross-Site Scripting (XSS)",
		Severity:    model.SeverityMedium,
	},
	"X-Frame-Options": {
		PresentDesc: "Clickjacking defense configured",
		MissingDesc: "Missing X-Frame-Options allows UI redressing / clickjacking",
		Severity:    model.SeverityLow,
	},
	"X-Content-Type-Options": {
		PresentDesc: "MIME sniffing protection enabled",
		MissingDesc: "Missing X-Content-Type-Options: nosniff allows MIME confusion",
		Severity:    model.SeverityLow,
	},
	"Referrer-Policy": {
		PresentDesc: "Referrer policy defined",
		MissingDesc: "Missing Referrer-Policy may leak URL path/tokens to external origins",
		Severity:    model.SeverityInfo,
	},
	"Permissions-Policy": {
		PresentDesc: "Permissions policy defined",
		MissingDesc: "Missing Permissions-Policy leaves browser APIs unrestricted",
		Severity:    model.SeverityInfo,
	},
}

func (m *Module) Run(ctx context.Context, req engine.Request, emit func(model.Finding) error) (*model.ModuleResult, error) {
	domain := scope.CanonicalizeDomain(req.Target)
	var findings []model.Finding

	targetURL := req.Target
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = fmt.Sprintf("https://%s", domain)
	}

	resp, err := req.Client.Get(ctx, targetURL, nil)
	if err != nil {
		if strings.HasPrefix(targetURL, "https://") {
			targetURL = "http://" + strings.TrimPrefix(targetURL, "https://")
			resp, err = req.Client.Get(ctx, targetURL, nil)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to reach target for header analysis: %w", err)
	}

	rawHeaders := make(map[string]string)
	for k, v := range resp.Headers {
		if len(v) > 0 {
			rawHeaders[k] = v[0]
		}
	}

	var missingHeaders []string
	for hName, check := range standardChecks {
		var val string
		for k, v := range rawHeaders {
			if strings.EqualFold(k, hName) {
				val = v
				break
			}
		}

		if val != "" {
			f := model.Finding{
				ID:        fmt.Sprintf("header-present-%s-%s", strings.ToLower(hName), domain),
				Module:    m.ID(),
				Target:    domain,
				Title:     fmt.Sprintf("%s: Present", hName),
				Detail:    fmt.Sprintf("%s: %s", check.PresentDesc, val),
				Severity:  model.SeverityInfo,
				Timestamp: time.Now().UTC(),
			}
			findings = append(findings, f)
			_ = emit(f)
		} else {
			missingHeaders = append(missingHeaders, hName)
			f := model.Finding{
				ID:        fmt.Sprintf("header-missing-%s-%s", strings.ToLower(hName), domain),
				Module:    m.ID(),
				Target:    domain,
				Title:     fmt.Sprintf("Missing Security Header: %s", hName),
				Detail:    check.MissingDesc,
				Severity:  check.Severity,
				Timestamp: time.Now().UTC(),
			}
			findings = append(findings, f)
			_ = emit(f)
		}
	}

	// CORS Evaluation
	acao := rawHeaders["Access-Control-Allow-Origin"]
	acac := strings.ToLower(rawHeaders["Access-Control-Allow-Credentials"])

	if acao == "*" {
		if acac == "true" {
			f := model.Finding{
				ID:        fmt.Sprintf("cors-wildcard-cred-%s", domain),
				Module:    m.ID(),
				Target:    domain,
				Title:     "Critical CORS Misconfiguration: Wildcard with Credentials",
				Detail:    "Access-Control-Allow-Origin: * paired with Allow-Credentials: true permits cross-origin session hijacking.",
				Severity:  model.SeverityCritical,
				Timestamp: time.Now().UTC(),
			}
			findings = append(findings, f)
			_ = emit(f)
		} else {
			f := model.Finding{
				ID:        fmt.Sprintf("cors-wildcard-%s", domain),
				Module:    m.ID(),
				Target:    domain,
				Title:     "CORS Wildcard Allowed",
				Detail:    "Access-Control-Allow-Origin: * allows any origin to read responses.",
				Severity:  model.SeverityLow,
				Timestamp: time.Now().UTC(),
			}
			findings = append(findings, f)
			_ = emit(f)
		}
	} else if acao == "null" {
		f := model.Finding{
			ID:        fmt.Sprintf("cors-null-%s", domain),
			Module:    m.ID(),
			Target:    domain,
			Title:     "CORS Null Origin Allowed",
			Detail:    "ACAO: null allows sandboxed iframes to access cross-origin response data.",
			Severity:  model.SeverityHigh,
			Timestamp: time.Now().UTC(),
		}
		findings = append(findings, f)
		_ = emit(f)
	}

	// Cookie Flags Analysis
	for _, c := range resp.Cookies {
		if !c.Secure && strings.HasPrefix(targetURL, "https://") {
			f := model.Finding{
				ID:        fmt.Sprintf("cookie-insecure-%s-%s", c.Name, domain),
				Module:    m.ID(),
				Target:    domain,
				Title:     fmt.Sprintf("Insecure Cookie Flag: %s", c.Name),
				Detail:    fmt.Sprintf("Cookie %s is missing the 'Secure' attribute.", c.Name),
				Severity:  model.SeverityLow,
				Timestamp: time.Now().UTC(),
			}
			findings = append(findings, f)
			_ = emit(f)
		}
		if !c.HttpOnly {
			f := model.Finding{
				ID:        fmt.Sprintf("cookie-nohttponly-%s-%s", c.Name, domain),
				Module:    m.ID(),
				Target:    domain,
				Title:     fmt.Sprintf("Cookie Missing HttpOnly: %s", c.Name),
				Detail:    fmt.Sprintf("Cookie %s is readable by client-side JavaScript.", c.Name),
				Severity:  model.SeverityLow,
				Timestamp: time.Now().UTC(),
			}
			findings = append(findings, f)
			_ = emit(f)
		}
	}

	data := map[string]interface{}{
		"headers":         rawHeaders,
		"missing_headers": missingHeaders,
		"cors": map[string]string{
			"acao": acao,
			"acac": acac,
		},
		"cookie_count": len(resp.Cookies),
	}

	return &model.ModuleResult{
		Module:    m.ID(),
		Target:    domain,
		Findings:  findings,
		Data:      data,
		Timestamp: time.Now().UTC(),
	}, nil
}

