package transport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/MohammadAliMehri/ReconSaas/internal/scope"
)

func TestScopedClient_GetAndLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom-Header", "ReconSaas")
		_, _ = w.Write([]byte("Hello, Recon!"))
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL)
	engine, err := scope.NewEngine(scope.Policy{
		AllowDomains:        []string{u.Hostname()},
		DenyPrivateNetworks: false, // allow local test server
	})
	if err != nil {
		t.Fatalf("unexpected error creating scope engine: %v", err)
	}

	client := NewScopedClient(engine, Config{
		Timeout:          5 * time.Second,
		MaxResponseBytes: 1024,
	})

	ctx := context.Background()
	resp, err := client.Get(ctx, server.URL, nil)
	if err != nil {
		t.Fatalf("client.Get failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	if string(resp.Body) != "Hello, Recon!" {
		t.Errorf("expected body 'Hello, Recon!', got %q", string(resp.Body))
	}
	if resp.Headers.Get("X-Custom-Header") != "ReconSaas" {
		t.Errorf("missing custom header")
	}
}

func TestScopedClient_OutOfScopeBlocked(t *testing.T) {
	engine, err := scope.NewEngine(scope.Policy{
		AllowDomains:        []string{"authorized.com"},
		DenyPrivateNetworks: true,
	})
	if err != nil {
		t.Fatalf("unexpected error creating scope engine: %v", err)
	}

	client := NewScopedClient(engine, Config{
		Timeout: 5 * time.Second,
	})

	ctx := context.Background()
	_, err = client.Get(ctx, "https://unauthorized-domain.com", nil)
	if err == nil {
		t.Errorf("expected out-of-scope error, got nil")
	}
}

func TestScopedClient_ByteLimitExceeded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("12345678901234567890")) // 20 bytes
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL)
	engine, err := scope.NewEngine(scope.Policy{
		AllowDomains:        []string{u.Hostname()},
		DenyPrivateNetworks: false,
	})
	if err != nil {
		t.Fatalf("unexpected error creating scope engine: %v", err)
	}

	client := NewScopedClient(engine, Config{
		Timeout:          5 * time.Second,
		MaxResponseBytes: 10, // only allow 10 bytes
	})

	ctx := context.Background()
	_, err = client.Get(ctx, server.URL, nil)
	if err != ErrResponseTooLarge {
		t.Errorf("expected ErrResponseTooLarge, got %v", err)
	}
}

