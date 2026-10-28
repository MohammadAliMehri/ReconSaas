package scope

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

var (
	ErrOutOfScope        = errors.New("target is out of scope")
	ErrPrivateIPDenied   = errors.New("access to private/local/metadata network address is denied")
	ErrInvalidTarget     = errors.New("invalid target format")
	ErrUnresolvedAddress = errors.New("target address could not be resolved or validated")
)

// Policy defines the scoping boundaries for reconnaissance operations.
type Policy struct {
	AllowDomains        []string   `yaml:"allow_domains" json:"allow_domains"`
	AllowCIDRs          []*net.IPNet `yaml:"-" json:"-"`
	AllowCIDRStrings    []string   `yaml:"allow_cidrs" json:"allow_cidrs"`
	DenyPrivateNetworks bool       `yaml:"deny_private_networks" json:"deny_private_networks"`
	FollowRedirects     bool       `yaml:"follow_redirects" json:"follow_redirects"`
}

// Engine evaluates URLs, hostnames, and IP addresses against a defined Policy.
type Engine struct {
	policy Policy
}

// NewEngine creates a new scope Engine after compiling and validating CIDRs.
func NewEngine(policy Policy) (*Engine, error) {
	var parsedCIDRs []*net.IPNet
	for _, raw := range policy.AllowCIDRStrings {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid allow CIDR %q: %w", raw, err)
		}
		parsedCIDRs = append(parsedCIDRs, ipNet)
	}
	policy.AllowCIDRs = parsedCIDRs

	return &Engine{policy: policy}, nil
}

// IsDomainAllowed checks whether a hostname matches the allowlist.
func (e *Engine) IsDomainAllowed(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if colon := strings.Index(host, ":"); colon != -1 {
		host = host[:colon]
	}

	if len(e.policy.AllowDomains) == 0 {
		// If no domain allowlist is specified, all domains are eligible unless denied by IP/CIDR policy
		return true
	}

	for _, pattern := range e.policy.AllowDomains {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}
		if pattern == host {
			return true
		}
		if strings.HasPrefix(pattern, "*.") {
			root := strings.TrimPrefix(pattern, "*.")
			if host == root || strings.HasSuffix(host, "."+root) {
				return true
			}
		}
	}
	return false
}

// IsIPAllowed checks if an IP is within the allowed CIDRs and not blocked by private network restrictions.
func (e *Engine) IsIPAllowed(ip net.IP) error {
	if ip == nil {
		return ErrUnresolvedAddress
	}

	if e.policy.DenyPrivateNetworks {
		if isPrivateOrSpecialIP(ip) {
			return fmt.Errorf("%w: %s", ErrPrivateIPDenied, ip.String())
		}
	}

	if len(e.policy.AllowCIDRs) == 0 {
		return nil
	}

	for _, cidr := range e.policy.AllowCIDRs {
		if cidr.Contains(ip) {
			return nil
		}
	}

	return fmt.Errorf("%w: ip %s is not in allowed CIDRs", ErrOutOfScope, ip.String())
}

// ValidateURL checks whether a full URL meets domain and IP scope criteria.
func (e *Engine) ValidateURL(rawURL string) error {
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidTarget, err)
	}

	host := parsed.Hostname()
	if host == "" {
		return ErrInvalidTarget
	}

	// If host is an IP literal, validate IP directly
	if ip := net.ParseIP(host); ip != nil {
		return e.IsIPAllowed(ip)
	}

	// Validate domain name
	if !e.IsDomainAllowed(host) {
		return fmt.Errorf("%w: domain %s is not allowed", ErrOutOfScope, host)
	}

	return nil
}

// isPrivateOrSpecialIP checks for loopback, RFC 1918, RFC 6598 (CGNAT), link-local (169.254.x.x), multicast, or documentation IPs.
func isPrivateOrSpecialIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsUnspecified() {
		return true
	}

	// IPv4 checks
	if ipv4 := ip.To4(); ipv4 != nil {
		// 10.0.0.0/8
		if ipv4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ipv4[0] == 172 && ipv4[1] >= 16 && ipv4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ipv4[0] == 192 && ipv4[1] == 168 {
			return true
		}
		// 100.64.0.0/10 (Carrier-Grade NAT)
		if ipv4[0] == 100 && (ipv4[1]&0xc0 == 64) {
			return true
		}
		// 169.254.0.0/16 (Link Local / Cloud Metadata)
		if ipv4[0] == 169 && ipv4[1] == 254 {
			return true
		}
		// 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (TEST-NET)
		if (ipv4[0] == 192 && ipv4[1] == 0 && ipv4[2] == 2) ||
			(ipv4[0] == 198 && ipv4[1] == 51 && ipv4[2] == 100) ||
			(ipv4[0] == 203 && ipv4[1] == 0 && ipv4[2] == 113) {
			return true
		}
		return false
	}

	// IPv6 Unique Local (fc00::/7)
	if len(ip) == net.IPv6len && (ip[0]&0xfe) == 0xfc {
		return true
	}

	return false
}

// CanonicalizeDomain extracts a normalized domain string without protocol or trailing slashes.
func CanonicalizeDomain(raw string) string {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "http://") {
		raw = strings.TrimPrefix(raw, "http://")
	} else if strings.HasPrefix(raw, "https://") {
		raw = strings.TrimPrefix(raw, "https://")
	}
	if slash := strings.Index(raw, "/"); slash != -1 {
		raw = raw[:slash]
	}
	if colon := strings.Index(raw, ":"); colon != -1 {
		raw = raw[:colon]
	}
	return strings.ToLower(raw)
}

