package scope

import (
	"net"
	"testing"
)

func TestScopeEngine_DomainMatching(t *testing.T) {
	policy := Policy{
		AllowDomains:        []string{"example.com", "*.target.corp"},
		DenyPrivateNetworks: true,
	}

	engine, err := NewEngine(policy)
	if err != nil {
		t.Fatalf("unexpected error creating scope engine: %v", err)
	}

	tests := []struct {
		host    string
		allowed bool
	}{
		{"example.com", true},
		{"sub.example.com", false},
		{"target.corp", true},
		{"api.target.corp", true},
		{"deep.sub.target.corp", true},
		{"attacker.com", false},
		{"not-target.corp", false},
	}

	for _, tc := range tests {
		got := engine.IsDomainAllowed(tc.host)
		if got != tc.allowed {
			t.Errorf("IsDomainAllowed(%q) = %v, expected %v", tc.host, got, tc.allowed)
		}
	}
}

func TestScopeEngine_PrivateIPDenial(t *testing.T) {
	policy := Policy{
		DenyPrivateNetworks: true,
	}

	engine, err := NewEngine(policy)
	if err != nil {
		t.Fatalf("unexpected error creating scope engine: %v", err)
	}

	tests := []struct {
		ipStr     string
		shouldErr bool
	}{
		{"127.0.0.1", true},
		{"10.0.1.5", true},
		{"172.16.50.1", true},
		{"192.168.1.1", true},
		{"169.254.169.254", true},
		{"100.64.0.1", true},
		{"::1", true},
		{"fc00::1", true},
		{"8.8.8.8", false},
		{"93.184.216.34", false},
	}

	for _, tc := range tests {
		ip := net.ParseIP(tc.ipStr)
		err := engine.IsIPAllowed(ip)
		if tc.shouldErr && err == nil {
			t.Errorf("IsIPAllowed(%q) succeeded, expected denial", tc.ipStr)
		} else if !tc.shouldErr && err != nil {
			t.Errorf("IsIPAllowed(%q) failed: %v, expected allow", tc.ipStr, err)
		}
	}
}

func TestCanonicalizeDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://example.com/test", "example.com"},
		{"http://sub.example.com:8080/api", "sub.example.com"},
		{"Example.COM", "example.com"},
		{"target.corp:443", "target.corp"},
	}

	for _, tc := range tests {
		got := CanonicalizeDomain(tc.input)
		if got != tc.expected {
			t.Errorf("CanonicalizeDomain(%q) = %q, expected %q", tc.input, got, tc.expected)
		}
	}
}

