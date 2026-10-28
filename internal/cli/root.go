package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/MohammadAliMehri/ReconSaas/internal/analysis/rank"
	"github.com/MohammadAliMehri/ReconSaas/internal/config"
	"github.com/MohammadAliMehri/ReconSaas/internal/engine"
	"github.com/MohammadAliMehri/ReconSaas/internal/fingerprint"
	"github.com/MohammadAliMehri/ReconSaas/internal/model"
	"github.com/MohammadAliMehri/ReconSaas/internal/modules/active/bypass"
	"github.com/MohammadAliMehri/ReconSaas/internal/modules/active/dirs"
	"github.com/MohammadAliMehri/ReconSaas/internal/modules/active/endpoints"
	"github.com/MohammadAliMehri/ReconSaas/internal/modules/active/headers"
	"github.com/MohammadAliMehri/ReconSaas/internal/modules/active/ports"
	"github.com/MohammadAliMehri/ReconSaas/internal/modules/active/tech"
	"github.com/MohammadAliMehri/ReconSaas/internal/modules/passive/certs"
	"github.com/MohammadAliMehri/ReconSaas/internal/modules/passive/dns"
	"github.com/MohammadAliMehri/ReconSaas/internal/modules/passive/js"
	"github.com/MohammadAliMehri/ReconSaas/internal/modules/passive/wayback"
	"github.com/MohammadAliMehri/ReconSaas/internal/report"
	"github.com/MohammadAliMehri/ReconSaas/internal/scope"
	"github.com/MohammadAliMehri/ReconSaas/internal/transport"
)

var banner = `
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝

   ███████╗██████╗  █████╗ ███╗   ███╗███████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗
   ██╔════╝██╔══██╗██╔══██╗████╗ ████║██╔════╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝
   █████╗  ██████╔╝███████║██╔████╔██║█████╗  ██║ █╗ ██║██║   ██║██████╔╝█████╔╝
   ██╔══╝  ██╔══██╗██╔══██║██║╚██╔╝██║██╔══╝  ██║███╗██║██║   ██║██╔══██╗██╔═██╗
   ██║     ██║  ██║██║  ██║██║ ╚═╝ ██║███████╗╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗
   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝ ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝

  Zero-Cost Automated Reconnaissance Framework (Go v3.0)
`

type scanOptions struct {
	target      string
	targetsFile string
	mode        string
	output      string
	modules     string
	configFile  string
	authorized  bool
	dryRun      bool
	interactive bool
	threads     int
	timeout     int
	rateLimit   float64
	topPorts    int
	verbose     bool
}

var opts scanOptions

// NewRootCmd initializes the Cobra command tree.
func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "recon",
		Short: "ReconSaas v3.0 — Zero-cost automated reconnaissance CLI",
		Long:  banner + "\nReconSaas v3.0: High-performance, deterministic recon engine in Go.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.interactive {
				return runInteractive()
			}
			if opts.target != "" || opts.targetsFile != "" {
				return runScan()
			}
			return cmd.Help()
		},
	}

	addScanFlags(rootCmd)

	// Subcommands
	rootCmd.AddCommand(newScanCmd())
	rootCmd.AddCommand(newModulesCmd())
	rootCmd.AddCommand(newConfigCmd())
	rootCmd.AddCommand(newFingerprintsCmd())
	rootCmd.AddCommand(newVersionCmd())

	return rootCmd
}

func addScanFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&opts.target, "target", "t", "", "Target domain or URL")
	cmd.Flags().StringVarP(&opts.targetsFile, "targets", "T", "", "File with targets (one per line)")
	cmd.Flags().StringVarP(&opts.mode, "mode", "m", "passive", "Scan mode: passive | active | hybrid")
	cmd.Flags().StringVarP(&opts.output, "output", "o", "", "Output directory (default: ./recon-output/<target>)")
	cmd.Flags().StringVarP(&opts.modules, "modules", "M", "", "Comma-separated module IDs")
	cmd.Flags().StringVar(&opts.configFile, "config", "", "Path to YAML configuration file")
	cmd.Flags().BoolVar(&opts.authorized, "authorized", false, "Attestation required for active or hybrid mode")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "Preview execution plan and budgets without scanning")
	cmd.Flags().BoolVarP(&opts.interactive, "interactive", "i", false, "Launch interactive guided wizard")
	cmd.Flags().IntVar(&opts.threads, "threads", 10, "Concurrent threads (default: 10)")
	cmd.Flags().IntVar(&opts.timeout, "timeout", 30, "HTTP timeout in seconds (default: 30)")
	cmd.Flags().Float64Var(&opts.rateLimit, "rate-limit", 0.5, "Delay between requests in seconds (default: 0.5)")
	cmd.Flags().IntVar(&opts.topPorts, "top-ports", 1000, "Top N ports to scan (default: 1000)")
	cmd.Flags().BoolVarP(&opts.verbose, "verbose", "v", false, "Enable verbose debug output")
}

func newScanCmd() *cobra.Command {
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Execute reconnaissance scan against target(s)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan()
		},
	}
	addScanFlags(scanCmd)
	return scanCmd
}

func newModulesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "modules",
		Short: "Manage and list reconnaissance modules",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all available modules and their stage",
		Run: func(cmd *cobra.Command, args []string) {
			reg := buildRegistry()
			all := reg.List()

			fmt.Println("\nAvailable ReconSaas Modules:")
			fmt.Println("----------------------------------------------------------------------")
			fmt.Printf("%-12s %-10s %s\n", "ID", "PHASE", "DESCRIPTION")
			fmt.Println("----------------------------------------------------------------------")
			for _, m := range all {
				fmt.Printf("%-12s %-10s %s\n", m.ID(), strings.ToUpper(string(m.Phase())), m.Description())
			}
			fmt.Println("----------------------------------------------------------------------")
		},
	}

	cmd.AddCommand(listCmd)
	return cmd
}

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Configuration validation and utilities",
	}

	valCmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate a YAML configuration file",
		RunE: func(cmd *cobra.Command, args []string) error {
			path, _ := cmd.Flags().GetString("file")
			if path == "" {
				path = "configs/default.yaml"
			}
			cfg, err := config.Load(path)
			if err != nil {
				return fmt.Errorf("configuration validation FAILED: %w", err)
			}
			fmt.Printf("Configuration %s is VALID (mode: %s, modules: %d)\n", path, cfg.Mode, len(cfg.Modules.Enabled))
			return nil
		},
	}
	valCmd.Flags().StringP("file", "f", "", "Config file path to validate")

	cmd.AddCommand(valCmd)
	return cmd
}

func newFingerprintsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fingerprints",
		Short: "Validate and inspect fingerprint signatures",
	}

	valCmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate signature database",
		RunE: func(cmd *cobra.Command, args []string) error {
			eng, err := fingerprint.NewEngine()
			if err != nil {
				return err
			}
			fmt.Printf("Signatures VALID: successfully loaded embedded fingerprint database.\n")
			_ = eng
			return nil
		},
	}

	cmd.AddCommand(valCmd)
	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print ReconSaas version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("ReconSaas v%s (Go)\n", report.ToolVersion)
		},
	}
}

func runScan() error {
	fmt.Print(banner)

	var targets []string
	if opts.targetsFile != "" {
		data, err := os.ReadFile(opts.targetsFile)
		if err != nil {
			return fmt.Errorf("failed to read targets file %q: %w", opts.targetsFile, err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				targets = append(targets, line)
			}
		}
	} else if opts.target != "" {
		targets = append(targets, opts.target)
	} else {
		return fmt.Errorf("--target or --targets is required")
	}

	cfg := config.DefaultConfig()
	if opts.configFile != "" {
		var err error
		cfg, err = config.Load(opts.configFile)
		if err != nil {
			return err
		}
	}

	mode := model.Mode(opts.mode)
	if mode != model.ModePassive && mode != model.ModeActive && mode != model.ModeHybrid {
		return fmt.Errorf("invalid mode %q (must be passive, active, or hybrid)", opts.mode)
	}

	if (mode == model.ModeActive || mode == model.ModeHybrid) && !opts.authorized {
		return fmt.Errorf("active/hybrid scan requires operator attestation: add --authorized to proceed")
	}

	var selectedMods []string
	if opts.modules != "" {
		for _, m := range strings.Split(opts.modules, ",") {
			selectedMods = append(selectedMods, strings.TrimSpace(m))
		}
	}

	// Setup graceful interrupt cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n[!] Scan interrupted by operator. Cleaning up...")
		cancel()
	}()

	reg := buildRegistry()

	for _, target := range targets {
		domain := scope.CanonicalizeDomain(target)
		outDir := opts.output
		if outDir == "" {
			outDir = filepath.Join("recon-output", strings.ReplaceAll(domain, ":", "_"))
		}

		if opts.dryRun {
			fmt.Println("\n================= DRY-RUN PLAN =================")
			fmt.Printf("Target:     %s\n", domain)
			fmt.Printf("Mode:       %s\n", mode)
			fmt.Printf("Output:     %s\n", outDir)
			fmt.Printf("Threads:    %d\n", opts.threads)
			fmt.Printf("Rate limit: %.2fs\n", opts.rateLimit)
			fmt.Printf("Modules:    %s\n", strings.Join(selectedMods, ", "))
			fmt.Println("================================================")
			continue
		}

		scopePolicy := cfg.ToScopePolicy()
		scopePolicy.AllowDomains = append(scopePolicy.AllowDomains, domain, "*."+domain)
		scopeEng, err := scope.NewEngine(scopePolicy)
		if err != nil {
			return err
		}

		transportCfg := transport.Config{
			Timeout:         time.Duration(opts.timeout) * time.Second,
			RateLimitDelay:  time.Duration(opts.rateLimit * float64(time.Second)),
			FollowRedirects: false,
		}
		client := transport.NewScopedClient(scopeEng, transportCfg)

		orch, err := engine.NewOrchestrator(reg, scopeEng, client, engine.OrchestratorConfig{
			Target:          target,
			Mode:            mode,
			OutputDir:       outDir,
			Authorized:      opts.authorized,
			MaxConcurrency:  opts.threads,
			SelectedModules: selectedMods,
		})
		if err != nil {
			return err
		}

		fmt.Printf("\n[*] Starting scan on target: %s (mode: %s)\n", domain, mode)
		start := time.Now()

		var emittedFindings []model.Finding
		customEmit := func(f model.Finding) error {
			emittedFindings = append(emittedFindings, f)
			_ = orch.EmitFinding(f)
			fmt.Printf("  [%s] %s: %s\n", strings.ToUpper(string(f.Severity)), f.Module, f.Title)
			return nil
		}
		_ = customEmit

		results, err := orch.Execute(ctx)
		if err != nil && err != context.Canceled {
			fmt.Printf("[!] Warning during scan: %v\n", err)
		}

		// Compile and generate final reports
		repGen := report.NewGenerator(outDir, domain, mode)
		if err := repGen.Generate(results, emittedFindings); err != nil {
			fmt.Printf("[!] Failed to render reports: %v\n", err)
		} else {
			fmt.Printf("[+] Reports generated successfully:\n")
			fmt.Printf("    Markdown: %s/report.md\n", outDir)
			fmt.Printf("    JSON:     %s/report.json\n", outDir)
		}

		fmt.Printf("[*] Completed in %.2fs\n", time.Since(start).Seconds())
	}

	return nil
}

func runInteractive() error {
	fmt.Print(banner)
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("\n[?] Enter target domain: ")
	target, _ := reader.ReadString('\n')
	target = strings.TrimSpace(target)
	if target == "" {
		return fmt.Errorf("target cannot be empty")
	}

	fmt.Println("\nSelect Scan Mode:")
	fmt.Println("  1) Passive (OSINT, DNS, CT logs, Wayback) [Default]")
	fmt.Println("  2) Active  (Ports, Dirs, Headers, Fingerprinting)")
	fmt.Println("  3) Hybrid   (Passive first, then Active)")
	fmt.Print("[?] Select mode [1-3]: ")
	modeChoice, _ := reader.ReadString('\n')
	modeChoice = strings.TrimSpace(modeChoice)

	mode := "passive"
	authorized := false
	if modeChoice == "2" {
		mode = "active"
		authorized = true
	} else if modeChoice == "3" {
		mode = "hybrid"
		authorized = true
	}

	opts.target = target
	opts.mode = mode
	opts.authorized = authorized

	return runScan()
}

func buildRegistry() *engine.Registry {
	reg := engine.NewRegistry()

	_ = reg.Register(dns.New())
	_ = reg.Register(certs.New())
	_ = reg.Register(wayback.New())
	_ = reg.Register(js.New())

	_ = reg.Register(ports.New())
	if techMod, err := tech.New(); err == nil {
		_ = reg.Register(techMod)
	}
	_ = reg.Register(headers.New())
	_ = reg.Register(dirs.New())
	_ = reg.Register(endpoints.New())
	_ = reg.Register(bypass.New())

	_ = reg.Register(rank.New())

	return reg
}

