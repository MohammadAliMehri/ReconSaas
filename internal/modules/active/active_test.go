package active_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/MohammadAliMehri/ReconSaas/internal/engine"
	"github.com/MohammadAliMehri/ReconSaas/internal/model"
	"github.com/MohammadAliMehri/ReconSaas/internal/modules/active/bypass"
	"github.com/MohammadAliMehri/ReconSaas/internal/modules/active/dirs"
	"github.com/MohammadAliMehri/ReconSaas/internal/modules/active/endpoints"
	"github.com/MohammadAliMehri/ReconSaas/internal/modules/active/headers"
	"github.com/MohammadAliMehri/ReconSaas/internal/modules/active/ports"
	"github.com/MohammadAliMehri/ReconSaas/internal/modules/active/tech"
	"github.com/MohammadAliMehri/ReconSaas/internal/scope"
	"github.com/MohammadAliMehri/ReconSaas/internal/transport"
)

func TestActiveModules_Contracts(t *testing.T) {
	techMod, err := tech.New()
	if err != nil {
		t.Fatalf("failed to create tech module: %v", err)
	}

	mods := []engine.Module{
		ports.New(),
		techMod,
		headers.New(),
		dirs.New(),
		endpoints.New(),
		bypass.New(),
	}

	for _, m := range mods {
		if m.ID() == "" {
			t.Errorf("module ID cannot be empty")
		}
		if m.Phase() != model.ModeActive {
			t.Errorf("module %s expected phase active, got %s", m.ID(), m.Phase())
		}
		if m.Description() == "" {
			t.Errorf("module %s description cannot be empty", m.ID())
		}
	}
}

func TestHeadersModule_CORSWildcardDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL)
	engineScope, _ := scope.NewEngine(scope.Policy{
		AllowDomains:        []string{u.Hostname()},
		DenyPrivateNetworks: false,
	})
	client := transport.NewScopedClient(engineScope, transport.Config{})

	mod := headers.New()
	var emitted []model.Finding
	req := engine.Request{
		Target:     server.URL,
		Scope:      engineScope,
		Client:     client,
		Config:     make(map[string]interface{}),
		SharedData: &sync.Map{},
	}

	res, err := mod.Run(context.Background(), req, func(f model.Finding) error {
		emitted = append(emitted, f)
		return nil
	})
	if err != nil {
		t.Fatalf("headers.Run failed: %v", err)
	}

	criticalFound := false
	for _, f := range emitted {
		if f.Severity == model.SeverityCritical && f.Module == "headers" {
			criticalFound = true
			break
		}
	}
	if !criticalFound {
		t.Errorf("expected critical CORS finding, but none emitted. Findings: %+v", res.Findings)
	}
}

