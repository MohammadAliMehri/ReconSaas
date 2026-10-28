package certs

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/MohammadAliMehri/ReconSaas/internal/engine"
	"github.com/MohammadAliMehri/ReconSaas/internal/model"
	"github.com/MohammadAliMehri/ReconSaas/internal/scope"
)

type crtShEntry struct {
	NameValue  string `json:"name_value"`
	IssuerName string `json:"issuer_name"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
}

type otxResponse struct {
	PassiveDNS []struct {
		Hostname string `json:"hostname"`
	} `json:"passive_dns"`
}

// Module discovers subdomains via Certificate Transparency and passive DNS logs.
type Module struct{}

// New creates a certs module instance.
func New() *Module {
	return &Module{}
}

func (m *Module) ID() string          { return "certs" }
func (m *Module) Phase() model.Mode   { return model.ModePassive }
func (m *Module) Description() string { return "Certificate Transparency & Passive DNS" }

var interestingPrefixes = []string{
	"admin", "internal", "dev", "staging", "stage", "test", "qa",
	"vpn", "mail", "webmail", "portal", "api", "auth", "sso",
	"jenkins", "gitlab", "grafana", "kibana", "elastic", "jira",
	"confluence", "bitbucket", "harbor", "docker", "k8s", "kube",
	"prometheus", "consul", "vault", "argocd",
}

func (m *Module) Run(ctx context.Context, req engine.Request, emit func(model.Finding) error) (*model.ModuleResult, error) {
	domain := scope.CanonicalizeDomain(req.Target)
	subdomains := make(map[string]bool)
	issuerOrgs := make(map[string]bool)
	var certificates []map[string]string
	var findings []model.Finding

	// 1. Query crt.sh
	crtURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	if resp, err := req.Client.Get(ctx, crtURL, nil); err == nil && resp.StatusCode == 200 {
		var certList []crtShEntry
		if err := json.Unmarshal(resp.Body, &certList); err == nil {
			for _, cert := range certList {
				for _, line := range strings.Split(cert.NameValue, "\n") {
					sub := strings.ToLower(strings.TrimSpace(line))
					if sub != "" && !strings.Contains(sub, "*") {
						if sub == domain || strings.HasSuffix(sub, "."+domain) {
							subdomains[sub] = true
						}
					}
				}

				if cert.IssuerName != "" {
					for _, part := range strings.Split(cert.IssuerName, ",") {
						if strings.HasPrefix(strings.TrimSpace(part), "O=") {
							org := strings.TrimPrefix(strings.TrimSpace(part), "O=")
							issuerOrgs[org] = true
						}
					}
				}

				certificates = append(certificates, map[string]string{
					"name":       cert.NameValue,
					"issuer":     cert.IssuerName,
					"not_before": cert.NotBefore,
					"not_after":  cert.NotAfter,
				})
			}
		}
	}

	// 2. Query AlienVault OTX
	otxURL := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)
	if resp, err := req.Client.Get(ctx, otxURL, nil); err == nil && resp.StatusCode == 200 {
		var otx otxResponse
		if err := json.Unmarshal(resp.Body, &otx); err == nil {
			for _, entry := range otx.PassiveDNS {
				h := strings.ToLower(strings.TrimSpace(entry.Hostname))
				if h == domain || strings.HasSuffix(h, "."+domain) {
					subdomains[h] = true
				}
			}
		}
	}

	// 3. Query Shodan CTL
	shodanURL := fmt.Sprintf("https://ctl.shodan.io/api/v1/domain/%s/hostnames", domain)
	if resp, err := req.Client.Get(ctx, shodanURL, nil); err == nil && resp.StatusCode == 200 {
		var hostnames []string
		if err := json.Unmarshal(resp.Body, &hostnames); err == nil {
			for _, h := range hostnames {
				h = strings.ToLower(strings.TrimSpace(h))
				if h == domain || strings.HasSuffix(h, "."+domain) {
					subdomains[h] = true
				}
			}
		}
	}

	// 4. Query RapidDNS
	rapidURL := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", domain)
	if resp, err := req.Client.Get(ctx, rapidURL, nil); err == nil && resp.StatusCode == 200 {
		re := regexp.MustCompile(`(?i)<td>([a-zA-Z0-9.-]+\.` + regexp.QuoteMeta(domain) + `)</td>`)
		matches := re.FindAllStringSubmatch(string(resp.Body), -1)
		for _, m := range matches {
			if len(m) > 1 {
				subdomains[strings.ToLower(m[1])] = true
			}
		}
	}

	// Compile sorted subdomain list
	var subList []string
	var interesting []string
	for sub := range subdomains {
		subList = append(subList, sub)
		for _, p := range interestingPrefixes {
			if strings.HasPrefix(sub, p+".") || strings.Contains(sub, "."+p+".") {
				interesting = append(interesting, sub)
				break
			}
		}
	}
	sort.Strings(subList)
	sort.Strings(interesting)

	if len(subList) > 0 {
		f := model.Finding{
			ID:        fmt.Sprintf("certs-subdomains-%s", domain),
			Module:    m.ID(),
			Target:    domain,
			Title:     fmt.Sprintf("CT Logs: %d Subdomains Discovered", len(subList)),
			Detail:    fmt.Sprintf("Discovered %d subdomains from Certificate Transparency and passive DNS.", len(subList)),
			Severity:  model.SeverityInfo,
			Timestamp: time.Now().UTC(),
		}
		findings = append(findings, f)
		_ = emit(f)
	}

	if len(interesting) > 0 {
		sample := interesting
		if len(sample) > 20 {
			sample = sample[:20]
		}
		f := model.Finding{
			ID:        fmt.Sprintf("certs-interesting-%s", domain),
			Module:    m.ID(),
			Target:    domain,
			Title:     fmt.Sprintf("Interesting Subdomains Found (%d)", len(interesting)),
			Detail:    fmt.Sprintf("High-value assets detected: %s", strings.Join(sample, ", ")),
			Severity:  model.SeverityMedium,
			Timestamp: time.Now().UTC(),
		}
		findings = append(findings, f)
		_ = emit(f)
	}

	// Save subdomains to shared data for downstream active modules
	req.SharedData.Store("subdomains", subList)

	var orgList []string
	for org := range issuerOrgs {
		orgList = append(orgList, org)
	}
	sort.Strings(orgList)

	data := map[string]interface{}{
		"subdomains":       subList,
		"total_subdomains": len(subList),
		"interesting":      interesting,
		"issuer_orgs":      orgList,
		"certificates":     certificates,
	}

	return &model.ModuleResult{
		Module:    m.ID(),
		Target:    domain,
		Findings:  findings,
		Data:      data,
		Timestamp: time.Now().UTC(),
	}, nil
}

