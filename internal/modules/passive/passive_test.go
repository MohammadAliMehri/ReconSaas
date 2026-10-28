package passive_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/MohammadAliMehri/ReconSaas/internal/engine"
	"github.com/MohammadAliMehri/ReconSaas/internal/model"
	"github.com/MohammadAliMehri/ReconSaas/internal/modules/passive/certs"
	"github.com/MohammadAliMehri/ReconSaas/internal/modules/passive/dns"
	"github.com/MohammadAliMehri/ReconSaas/internal/modules/passive/js"
	"github.com/MohammadAliMehri/ReconSaas/internal/modules/passive/wayback"
	"github.com/MohammadAliMehri/ReconSaas/internal/scope"
	"github.com/MohammadAliMehri/ReconSaas/internal/transport"
)

func TestPassiveModules_Contracts(t *testing.T) {
	mods := []engine.Module{
		dns.New(),
		certs.New(),
		wayback.New(),
		js.New(),
	}

	for _, m := range mods {
		if m.ID() == "" {
			t.Errorf("module ID cannot be empty")
		}
		if m.Phase() != model.ModePassive {
			t.Errorf("module %s expected phase passive, got %s", m.ID(), m.Phase())
		}
		if m.Description() == "" {
			t.Errorf("module %s description cannot be empty", m.ID())
		}
	}
}

func TestJSModule_SecretMasking(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		script := `
			const aws = "AKIA1234567890ABCDEF";
			const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc";
			fetch("/api/v1/users");
		`
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(fmtScriptHTML(r.Host, script)))
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL)
	engineScope, _ := scope.NewEngine(scope.Policy{
		AllowDomains:        []string{u.Hostname()},
		DenyPrivateNetworks: false,
	})
	client := transport.NewScopedClient(engineScope, transport.Config{})

	mod := js.New()
	req := engine.Request{
		Target:     server.URL,
		Scope:      engineScope,
		Client:     client,
		Config:     map[string]interface{}{"authorized": true},
		SharedData: &sync.Map{},
	}

	res, err := mod.Run(context.Background(), req, func(f model.Finding) error { return nil })
	if err != nil {
		t.Fatalf("js.Run failed: %v", err)
	}

	secrets, ok := res.Data["secrets"].([]map[string]string)
	if !ok || len(secrets) == 0 {
		t.Fatalf("expected secrets detected, got %v", res.Data["secrets"])
	}

	for _, s := range secrets {
		val := s["value"]
		if s["type"] == "AWS Access Key ID" && (len(val) != 20 || val[4:] != "****************") {
			t.Errorf("AWS key was not properly masked: %s", val)
		}
	}
}

func fmtScriptHTML(host, scriptContent string) string {
	return `<!DOCTYPE html><html><body><script>` + scriptContent + `</script></body></html>`
}
