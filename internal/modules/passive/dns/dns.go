package dns

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/MohammadAliMehri/ReconSaas/internal/engine"
	"github.com/MohammadAliMehri/ReconSaas/internal/model"
	"github.com/MohammadAliMehri/ReconSaas/internal/scope"
)

// Module implements passive DNS enumeration.
type Module struct {
	resolver *net.Resolver
}

// New creates a new DNS module instance.
func New() *Module {
	return &Module{
		resolver: net.DefaultResolver,
	}
}

func (m *Module) ID() string          { return "dns" }
func (m *Module) Phase() model.Mode   { return model.ModePassive }
func (m *Module) Description() string { return "DNS Record & Wildcard Enumeration" }

func (m *Module) Run(ctx context.Context, req engine.Request, emit func(model.Finding) error) (*model.ModuleResult, error) {
	domain := scope.CanonicalizeDomain(req.Target)
	records := make(map[string][]string)
	var findings []model.Finding

	// A records
	if ips, err := m.resolver.LookupIP(ctx, "ip4", domain); err == nil && len(ips) > 0 {
		var list []string
		for _, ip := range ips {
			list = append(list, ip.String())
		}
		records["A"] = list
		f := model.Finding{
			ID:        fmt.Sprintf("dns-a-%s", domain),
			Module:    m.ID(),
			Target:    domain,
			Title:     fmt.Sprintf("DNS A Records (%d)", len(list)),
			Detail:    fmt.Sprintf("Resolved IPs: %s", strings.Join(list, ", ")),
			Severity:  model.SeverityInfo,
			Timestamp: time.Now().UTC(),
			Evidence: []model.Evidence{
				{Type: "dns_record", Source: domain, Data: list},
			},
		}
		findings = append(findings, f)
		_ = emit(f)
	}

	// AAAA records
	if ips, err := m.resolver.LookupIP(ctx, "ip6", domain); err == nil && len(ips) > 0 {
		var list []string
		for _, ip := range ips {
			list = append(list, ip.String())
		}
		records["AAAA"] = list
	}

	// MX records
	if mxList, err := m.resolver.LookupMX(ctx, domain); err == nil && len(mxList) > 0 {
		var list []string
		for _, mx := range mxList {
			list = append(list, fmt.Sprintf("%s (pref %d)", mx.Host, mx.Pref))
		}
		records["MX"] = list
		f := model.Finding{
			ID:        fmt.Sprintf("dns-mx-%s", domain),
			Module:    m.ID(),
			Target:    domain,
			Title:     fmt.Sprintf("MX Records Found (%d)", len(list)),
			Detail:    fmt.Sprintf("Mail exchangers: %s", strings.Join(list, ", ")),
			Severity:  model.SeverityInfo,
			Timestamp: time.Now().UTC(),
			Evidence: []model.Evidence{
				{Type: "dns_record", Source: domain, Data: list},
			},
		}
		findings = append(findings, f)
		_ = emit(f)
	}

	// NS records
	if nsList, err := m.resolver.LookupNS(ctx, domain); err == nil && len(nsList) > 0 {
		var list []string
		for _, ns := range nsList {
			list = append(list, ns.Host)
		}
		records["NS"] = list
	}

	// CNAME record
	if cname, err := m.resolver.LookupCNAME(ctx, domain); err == nil && cname != "" && cname != domain+"." {
		records["CNAME"] = []string{cname}
	}

	// TXT records (SPF, DMARC, Domain verification)
	if txtList, err := m.resolver.LookupTXT(ctx, domain); err == nil && len(txtList) > 0 {
		records["TXT"] = txtList
		for _, txt := range txtList {
			txtLower := strings.ToLower(txt)
			if strings.Contains(txtLower, "v=spf") {
				f := model.Finding{
					ID:        fmt.Sprintf("dns-spf-%s", domain),
					Module:    m.ID(),
					Target:    domain,
					Title:     "SPF Record Found",
					Detail:    txt,
					Severity:  model.SeverityInfo,
					Timestamp: time.Now().UTC(),
				}
				findings = append(findings, f)
				_ = emit(f)
			}
			if strings.Contains(txtLower, "v=dmarc") {
				f := model.Finding{
					ID:        fmt.Sprintf("dns-dmarc-%s", domain),
					Module:    m.ID(),
					Target:    domain,
					Title:     "DMARC Record Found",
					Detail:    txt,
					Severity:  model.SeverityInfo,
					Timestamp: time.Now().UTC(),
				}
				findings = append(findings, f)
				_ = emit(f)
			}
		}
	}

	// Wildcard DNS detection
	randBytes := make([]byte, 8)
	_, _ = rand.Read(randBytes)
	randSub := fmt.Sprintf("%s.%s", hex.EncodeToString(randBytes), domain)
	var wildcardIPs []string
	if ips, err := m.resolver.LookupIP(ctx, "ip4", randSub); err == nil && len(ips) > 0 {
		for _, ip := range ips {
			wildcardIPs = append(wildcardIPs, ip.String())
		}
		f := model.Finding{
			ID:        fmt.Sprintf("dns-wildcard-%s", domain),
			Module:    m.ID(),
			Target:    domain,
			Title:     "Wildcard DNS Detected",
			Detail:    fmt.Sprintf("Random subdomain %s resolved to: %s", randSub, strings.Join(wildcardIPs, ", ")),
			Severity:  model.SeverityInfo,
			Timestamp: time.Now().UTC(),
		}
		findings = append(findings, f)
		_ = emit(f)
	}

	data := map[string]interface{}{
		"records":      records,
		"wildcard_dns": wildcardIPs,
		"nameservers":  records["NS"],
	}

	return &model.ModuleResult{
		Module:    m.ID(),
		Target:    domain,
		Findings:  findings,
		Data:      data,
		Timestamp: time.Now().UTC(),
	}, nil
}

