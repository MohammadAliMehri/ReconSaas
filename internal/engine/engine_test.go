package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MohammadAliMehri/ReconSaas/internal/model"
	"github.com/MohammadAliMehri/ReconSaas/internal/scope"
)

type mockModule struct {
	id          string
	phase       model.Mode
	runExecuted bool
}

func (m *mockModule) ID() string          { return m.id }
func (m *mockModule) Phase() model.Mode   { return m.phase }
func (m *mockModule) Description() string { return "Mock module for testing" }

func (m *mockModule) Run(ctx context.Context, req Request, emit func(model.Finding) error) (*model.ModuleResult, error) {
	m.runExecuted = true
	_ = emit(model.Finding{
		ID:       m.id + "-1",
		Module:   m.id,
		Target:   req.Target,
		Title:    "Test finding",
		Severity: model.SeverityInfo,
	})
	return &model.ModuleResult{
		Module: m.id,
		Target: req.Target,
		Data:   map[string]interface{}{"status": "ok"},
	}, nil
}

func TestRegistry_RegisterAndRetrieve(t *testing.T) {
	reg := NewRegistry()
	mod := &mockModule{id: "dns", phase: model.ModePassive}

	if err := reg.Register(mod); err != nil {
		t.Fatalf("failed to register module: %v", err)
	}

	// Duplicate registration should fail
	if err := reg.Register(mod); err == nil {
		t.Errorf("expected error registering duplicate module, got nil")
	}

	retrieved, ok := reg.Get("dns")
	if !ok || retrieved.ID() != "dns" {
		t.Errorf("failed to retrieve registered module")
	}

	if len(reg.List()) != 1 {
		t.Errorf("expected 1 module in list, got %d", len(reg.List()))
	}
}

func TestOrchestrator_ActiveUnauthorizedBlocked(t *testing.T) {
	reg := NewRegistry()
	scopeEng, _ := scope.NewEngine(scope.Policy{})

	_, err := NewOrchestrator(reg, scopeEng, nil, OrchestratorConfig{
		Target:     "example.com",
		Mode:       model.ModeActive,
		Authorized: false, // Unauthorized!
	})

	if err != ErrActiveUnauthorized {
		t.Errorf("expected ErrActiveUnauthorized, got %v", err)
	}
}

func TestOrchestrator_ExecuteAndStreamEvents(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "recon-engine-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	reg := NewRegistry()
	modPassive := &mockModule{id: "passive-mod", phase: model.ModePassive}
	modActive := &mockModule{id: "active-mod", phase: model.ModeActive}
	_ = reg.Register(modPassive)
	_ = reg.Register(modActive)

	scopeEng, _ := scope.NewEngine(scope.Policy{})

	orch, err := NewOrchestrator(reg, scopeEng, nil, OrchestratorConfig{
		Target:     "example.com",
		Mode:       model.ModePassive,
		OutputDir:  tempDir,
		Authorized: false,
	})
	if err != nil {
		t.Fatalf("failed to create orchestrator: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results, err := orch.Execute(ctx)
	if err != nil {
		t.Fatalf("orchestrator execution failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 passive result, got %d", len(results))
	}
	if !modPassive.runExecuted {
		t.Errorf("passive module was not executed")
	}
	if modActive.runExecuted {
		t.Errorf("active module should not have run in passive mode")
	}

	// Check that events.jsonl was created and contains findings
	eventsPath := filepath.Join(tempDir, "events.jsonl")
	content, err := os.ReadFile(eventsPath)
	if err != nil {
		t.Fatalf("failed to read events.jsonl: %v", err)
	}
	if len(content) == 0 {
		t.Errorf("events.jsonl is empty")
	}
}

