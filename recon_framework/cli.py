"""
CLI Entry Point for Recon Framework.
"""
import argparse
import asyncio
import sys
import os

from . import __version__
from .config import ScanConfig
from .orchestrator import Orchestrator, PASSIVE_MODULES, ACTIVE_MODULES, ALL_MODULES
from .utils.logger import console


def parse_args():
    parser = argparse.ArgumentParser(
        prog="recon",
        description="Recon Framework — Zero-cost open-source reconnaissance platform",
        epilog="""
Examples:
  recon --target example.com --mode passive
  recon --target example.com --mode active
  recon --target example.com --mode hybrid
  recon --target example.com --mode active --modules dns,headers,js
  recon --targets targets.txt --mode passive
  recon --target example.com --mode hybrid -v --output ./my-recon
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Target(s)
    target_group = parser.add_mutually_exclusive_group(required=False)
    target_group.add_argument(
        "-t", "--target",
        help="Target domain or URL",
    )
    target_group.add_argument(
        "-T", "--targets",
        help="File with list of targets (one per line)",
    )

    # Mode
    parser.add_argument(
        "-m", "--mode",
        choices=["passive", "active", "hybrid"],
        default="hybrid",
        help="Recon mode (default: hybrid)",
    )

    # Output
    parser.add_argument(
        "-o", "--output",
        help="Output directory (default: ./recon-output/<target>)",
    )

    # Modules
    all_module_names = list(ALL_MODULES.keys())
    parser.add_argument(
        "-M", "--modules",
        help=f"Comma-separated list of modules to run. Available: {', '.join(all_module_names)}",
    )

    # Threading
    parser.add_argument(
        "--threads",
        type=int,
        default=10,
        help="Number of concurrent threads (default: 10)",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="HTTP timeout in seconds (default: 30)",
    )

    parser.add_argument(
        "--rate-limit",
        type=float,
        default=0.5,
        help="Seconds between requests (default: 0.5)",
    )

    # Port scan
    parser.add_argument(
        "--top-ports",
        type=int,
        default=1000,
        help="Number of top ports to scan (default: 1000)",
    )

    # Verbose
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose/debug logging",
    )

    # List modules
    parser.add_argument(
        "--list-modules",
        action="store_true",
        help="List all available modules and exit",
    )

    # Web UI
    parser.add_argument(
        "--web",
        action="store_true",
        help="Launch the web UI dashboard instead of CLI mode",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="Port for web UI (default: 5000, only with --web)",
    )

    # Version
    parser.add_argument(
        "--version",
        action="version",
        version=f"Recon Framework {__version__}",
    )

    return parser.parse_args()


def list_modules():
    """Print available modules."""
    console.print("\n[bold]Available Modules[/bold]\n")
    
    console.print("[bold blue]Passive Modules (no target contact):[/bold blue]")
    for name, cls in PASSIVE_MODULES.items():
        console.print(f"  [cyan]{name:15}[/cyan] — {cls.description}")
    
    console.print("\n[bold red]Active Modules (direct probing):[/bold red]")
    for name, cls in ACTIVE_MODULES.items():
        console.print(f"  [cyan]{name:15}[/cyan] — {cls.description}")
    
    console.print("\n[bold magenta]Analysis Modules:[/bold magenta]")
    for name, cls in ALL_MODULES.items():
        if name not in PASSIVE_MODULES and name not in ACTIVE_MODULES:
            console.print(f"  [cyan]{name:15}[/cyan] — {cls.description}")
    
    console.print()


def main():
    """Main entry point."""
    args = parse_args()

    if args.list_modules:
        list_modules()
        sys.exit(0)

    # Launch web UI
    if args.web:
        from .web.app import create_app
        console.print(f"\n[bold green]Starting Recon Framework Web UI...[/bold green]")
        console.print(f"[info]Dashboard:[/info] [cyan]http://localhost:{args.port}[/cyan]")
        console.print(f"[info]Press Ctrl+C to stop[/info]\n")
        app = create_app()
        app.run(host="0.0.0.0", port=args.port, debug=args.verbose)
        sys.exit(0)

    if not args.target and not args.targets:
        console.print("[error]--target or --targets is required[/error]")
        sys.exit(1)

    # Parse modules
    modules = None
    if args.modules:
        modules = [m.strip() for m in args.modules.split(",")]
        invalid = [m for m in modules if m not in ALL_MODULES]
        if invalid:
            console.print(f"[error]Unknown modules: {', '.join(invalid)}[/error]")
            console.print(f"[info]Available: {', '.join(ALL_MODULES.keys())}[/info]")
            sys.exit(1)

    # Handle targets file
    targets = []
    if args.targets:
        if not os.path.exists(args.targets):
            console.print(f"[error]Targets file not found: {args.targets}[/error]")
            sys.exit(1)
        with open(args.targets) as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    else:
        targets = [args.target]

    # Run for each target
    for target in targets:
        config = ScanConfig(
            target=target,
            mode=args.mode,
            output_dir=args.output or "",
            threads=args.threads,
            timeout=args.timeout,
            rate_limit=args.rate_limit,
            port_scan_top=args.top_ports,
            verbose=args.verbose,
            modules=modules or [],
        )

        orchestrator = Orchestrator(config)
        
        try:
            asyncio.run(orchestrator.run())
        except KeyboardInterrupt:
            console.print("\n[warning]Scan interrupted by user[/warning]")
            sys.exit(130)
        except Exception as e:
            console.print(f"\n[error]Fatal error: {e}[/error]")
            if args.verbose:
                import traceback
                traceback.print_exc()
            sys.exit(1)


if __name__ == "__main__":
    main()
