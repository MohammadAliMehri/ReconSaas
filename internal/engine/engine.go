package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/MohammadAliMehri/ReconSaas/internal/model"
	"github.com/MohammadAliMehri/ReconSaas/internal/scope"
	"github.com/MohammadAliMehri/ReconSaas/internal/transport"
)

var (
	ErrModuleNotFound     = errors.New("module not found in registry")
	ErrActiveUnauthorized = errors.New("active scan module requested without explicit operator authorization")
)

// Request contains the contextual parameters provided to a module at runtime.
type Request struct {
	Target     string
	Scope      *scope.Engine
	Client     transport.Client
	Config     map[string]interface{}
	SharedData *sync.Map
}

// Module defines the contract that all reconnaissance modules must satisfy.
type Module interface {
	ID() string
	Phase() model.Mode
	Description() string
	Run(ctx context.Context, req Request, emit func(model.Finding) error) (*model.ModuleResult, error)
}

// Registry manages the set of available reconnaissance modules.
type Registry struct {
	mu      sync.RWMutex
	modules map[string]Module
}

// NewRegistry initializes an empty module registry.
func NewRegistry() *Registry {
	return &Registry{
		modules: make(map[string]Module),
	}
}

// Register adds a module to the registry.
func (r *Registry) Register(m Module) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	id := m.ID()
	if _, exists := r.modules[id]; exists {
		return fmt.Errorf("module with ID %q already registered", id)
	}
	r.modules[id] = m
	return nil
}

// Get retrieves a module by ID.
func (r *Registry) Get(id string) (Module, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.modules[id]
	return m, ok
}

// List returns all registered modules.
func (r *Registry) List() []Module {
	r.mu.RLock()
	defer r.mu.RUnlock()

	list := make([]Module, 0, len(r.modules))
	for _, m := range r.modules {
		list = append(list, m)
	}
	return list
}

// OrchestratorConfig contains execution limits and parameters for the orchestrator.
type OrchestratorConfig struct {
	Target             string
	Mode               model.Mode
	OutputDir          string
	Authorized         bool // Required for Active / Hybrid mode
	MaxConcurrency     int
	PerHostConcurrency int
	SelectedModules    []string
}

// Orchestrator executes modules in staged order while coordinating concurrency, cancellation, and event logging.
type Orchestrator struct {
	registry    *Registry
	scopeEngine *scope.Engine
	client      transport.Client
	config      OrchestratorConfig
	sharedData  *sync.Map
	eventsMu    sync.Mutex
	eventsFile  *os.File
}

// NewOrchestrator builds an orchestrator instance.
func NewOrchestrator(
	reg *Registry,
	scopeEng *scope.Engine,
	client transport.Client,
	cfg OrchestratorConfig,
) (*Orchestrator, error) {
	if cfg.MaxConcurrency <= 0 {
		cfg.MaxConcurrency = 10
	}
	if (cfg.Mode == model.ModeActive || cfg.Mode == model.ModeHybrid) && !cfg.Authorized {
		return nil, ErrActiveUnauthorized
	}

	return &Orchestrator{
		registry:    reg,
		scopeEngine: scopeEng,
		client:      client,
		config:      cfg,
		sharedData:  &sync.Map{},
	}, nil
}

// InitializeStorage opens the events.jsonl file in the target directory.
func (o *Orchestrator) InitializeStorage() error {
	if err := os.MkdirAll(o.config.OutputDir, 0750); err != nil {
		return err
	}
	eventsPath := filepath.Join(o.config.OutputDir, "events.jsonl")
	f, err := os.OpenFile(eventsPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	o.eventsFile = f
	return nil
}

// Close releases open file resources.
func (o *Orchestrator) Close() error {
	if o.eventsFile != nil {
		return o.eventsFile.Close()
	}
	return nil
}

// EmitFinding writes a finding event atomically to disk and memory.
func (o *Orchestrator) EmitFinding(finding model.Finding) error {
	o.eventsMu.Lock()
	defer o.eventsMu.Unlock()

	if finding.Timestamp.IsZero() {
		finding.Timestamp = time.Now().UTC()
	}

	if o.eventsFile != nil {
		data, err := json.Marshal(finding)
		if err != nil {
			return err
		}
		data = append(data, '\n')
		if _, err := o.eventsFile.Write(data); err != nil {
			return err
		}
	}

	return nil
}

// Execute runs the modules designated for the target and mode.
func (o *Orchestrator) Execute(ctx context.Context) ([]*model.ModuleResult, error) {
	if err := o.InitializeStorage(); err != nil {
		return nil, fmt.Errorf("failed to initialize output storage: %w", err)
	}
	defer o.Close()

	modulesToRun := o.resolveModules()
	var results []*model.ModuleResult

	// Staged execution: Passive first, then Active
	phases := []model.Mode{model.ModePassive, model.ModeActive}
	for _, phase := range phases {
		for _, mod := range modulesToRun {
			if ctx.Err() != nil {
				return results, ctx.Err()
			}
			if mod.Phase() != phase {
				continue
			}
			if o.config.Mode == model.ModePassive && phase != model.ModePassive {
				continue
			}
			if o.config.Mode == model.ModeActive && phase != model.ModeActive {
				continue
			}

			req := Request{
				Target:     o.config.Target,
				Scope:      o.scopeEngine,
				Client:     o.client,
				Config:     make(map[string]interface{}),
				SharedData: o.sharedData,
			}

			start := time.Now()
			res, err := mod.Run(ctx, req, o.EmitFinding)
			if err != nil {
				res = &model.ModuleResult{
					Module:    mod.ID(),
					Target:    o.config.Target,
					Duration:  time.Since(start),
					Errors:    []string{err.Error()},
					Timestamp: time.Now().UTC(),
				}
			} else if res != nil {
				res.Duration = time.Since(start)
			}
			results = append(results, res)
		}
	}

	return results, nil
}

func (o *Orchestrator) resolveModules() []Module {
	all := o.registry.List()
	if len(o.config.SelectedModules) == 0 {
		return all
	}

	selectedSet := make(map[string]bool)
	for _, name := range o.config.SelectedModules {
		selectedSet[name] = true
	}

	var filtered []Module
	for _, m := range all {
		if selectedSet[m.ID()] {
			filtered = append(filtered, m)
		}
	}
	return filtered
}
