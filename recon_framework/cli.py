"""
Recon Framework v2.0 — CLI Entry Point
Zero-cost automated reconnaissance tool.
"""
import argparse
import asyncio
import sys
import os
import time

from . import __version__
from .config import ScanConfig
from .orchestrator import Orchestrator, PASSIVE_MODULES, ACTIVE_MODULES, ALL_MODULES
from .utils.logger import console


# ── Banner ───────────────────────────────────────────────────────

BANNER_LINES = [
    ("  ", "bold white", ""),
    ("  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗", "bold red", ""),
    ("  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║", "bold red", ""),
    ("  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║", "bold yellow", ""),
    ("  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║", "bold yellow", ""),
    ("  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║", "bold green", ""),
    ("  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝", "bold green", ""),
    ("  ", "dim", ""),
    ("   ███████╗██████╗  █████╗ ███╗   ███╗███████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗", "bold cyan", ""),
    ("   ██╔════╝██╔══██╗██╔══██╗████╗ ████║██╔════╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝", "bold cyan", ""),
    ("   █████╗  ██████╔╝███████║██╔████╔██║█████╗  ██║ █╗ ██║██║   ██║██████╔╝█████╔╝", "bold cyan", ""),
    ("   ██╔══╝  ██╔══██╗██╔══██║██║╚██╔╝██║██╔══╝  ██║███╗██║██║   ██║██╔══██╗██╔═██╗", "bold cyan", ""),
    ("   ██║     ██║  ██║██║  ██║██║ ╚═╝ ██║███████╗╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗", "bold cyan", ""),
    ("   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝ ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝", "bold cyan", ""),
]


def print_banner():
    """Print the full-color banner with GitHub link."""
    console.print()
    for text, style, _ in BANNER_LINES:
        console.print(f"[{style}]{text}[/{style}]")
    console.print()
    console.print("  [bold white]Zero-Cost Automated Reconnaissance Framework[/bold white]")
    console.print(f"  [dim]v{__version__}[/dim]  [dim]|[/dim]  [bold yellow]Passive[/bold yellow] [dim]|[/dim] [bold red]Active[/bold red] [dim]|[/dim] [bold magenta]Hybrid[/bold magenta]")
    console.print()
    console.print("  [bold green]GitHub:[/bold green] [bold cyan underline]https://github.com/MohammadAliMehri/ReconSaas[/bold cyan underline]")
    console.print("  [bold green]Author:[/bold green] [bold white]MohammadAliMehri[/bold white]")
    console.print()


# ── Interactive Menu ─────────────────────────────────────────────

def interactive_menu() -> dict:
    """Interactive menu — guided scan configuration."""
    print_banner()
    console.rule("[bold cyan]  Interactive Mode  [/bold cyan]")
    console.print()

    # Target
    console.print("[bold white]  [1] Target[/bold white]")
    target = console.input("  [bold cyan]>[/bold cyan] Enter target domain: ").strip()
    if not target:
        console.print("  [bold red]Target is required.[/bold red]")
        sys.exit(1)

    # Mode
    console.print()
    console.print("[bold white]  [2] Scan Mode[/bold white]")
    console.print("    [bold blue]  1[/bold blue]) Passive   — No contact. OSINT, DNS, CT logs, Wayback")
    console.print("    [bold red]  2[/bold red]) Active    — Direct probe. Ports, dirs, headers, fingerprint")
    console.print("    [bold magenta]  3[/bold magenta]) Hybrid    — Passive first, then Active on ranked targets [dim](recommended)[/dim]")
    mode_choice = console.input("  [bold cyan]>[/bold cyan] Select mode [dim][1/2/3, default=3][/dim]: ").strip()
    mode_map = {"1": "passive", "2": "active", "3": "hybrid", "": "hybrid"}
    mode = mode_map.get(mode_choice, "hybrid")

    # Modules
    console.print()
    console.print("[bold white]  [3] Modules[/bold white]")
    if mode == "passive":
        available = list(PASSIVE_MODULES.keys())
    elif mode == "active":
        available = list(ACTIVE_MODULES.keys())
    else:
        available = list(PASSIVE_MODULES.keys()) + list(ACTIVE_MODULES.keys())

    for i, name in enumerate(available, 1):
        cls = ALL_MODULES.get(name)
        desc = cls.description if cls else ""
        console.print(f"    [bold cyan]{i:2}[/bold cyan]) [bold]{name:12}[/bold] [dim]{desc}[/dim]")
    console.print(f"    [dim]Press Enter to run all modules, or comma-separated numbers (e.g. 1,3,5)[/dim]")
    mod_input = console.input("  [bold cyan]>[/bold cyan] Modules: ").strip()
    modules = None
    if mod_input:
        try:
            indices = [int(x.strip()) - 1 for x in mod_input.split(",")]
            modules = [available[i] for i in indices if 0 <= i < len(available)]
        except (ValueError, IndexError):
            console.print("  [yellow]Invalid selection — running all modules.[/yellow]")

    # Threads
    console.print()
    console.print("[bold white]  [4] Concurrency[/bold white]")
    threads_input = console.input("  [bold cyan]>[/bold cyan] Threads [dim][default=10][/dim]: ").strip()
    threads = int(threads_input) if threads_input.isdigit() else 10

    # Verbose
    console.print()
    verbose_input = console.input("  [bold cyan]>[/bold cyan] Verbose logging? [dim][y/N][/dim]: ").strip().lower()
    verbose = verbose_input in ("y", "yes")

    # Confirm
    console.print()
    console.rule("[bold green]  Scan Summary  [/bold green]")
    console.print(f"  [bold]Target:[/bold]     [cyan]{target}[/cyan]")
    console.print(f"  [bold]Mode:[/bold]       [{mode}]{mode}[/{mode}]")
    console.print(f"  [bold]Modules:[/bold]    {', '.join(modules) if modules else 'all'}")
    console.print(f"  [bold]Threads:[/bold]    {threads}")
    console.print(f"  [bold]Verbose:[/bold]    {'yes' if verbose else 'no'}")
    console.print()

    confirm = console.input("  [bold cyan]>[/bold cyan] Start scan? [dim][Y/n][/dim]: ").strip().lower()
    if confirm in ("n", "no"):
        console.print("  [yellow]Cancelled.[/yellow]")
        sys.exit(0)

    return {
        "target": target,
        "mode": mode,
        "modules": modules,
        "threads": threads,
        "verbose": verbose,
    }


# ── CLI Parser ──────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        prog="recon",
        description="Recon Framework v2.0 — Zero-cost automated reconnaissance CLI",
        epilog="""
Examples:
  recon --target example.com --mode hybrid
  recon --target example.com --mode passive -v
  recon --target example.com --mode active --modules dns,tech,headers
  recon --targets targets.txt --mode passive
  recon -i                              # interactive menu
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    target_group = parser.add_mutually_exclusive_group(required=False)
    target_group.add_argument("-t", "--target", help="Target domain or URL")
    target_group.add_argument("-T", "--targets", help="File with targets (one per line)")

    parser.add_argument("-m", "--mode", choices=["passive", "active", "hybrid"], default="hybrid",
                        help="Scan mode (default: hybrid)")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("-M", "--modules",
                        help=f"Comma-separated modules. Available: {', '.join(ALL_MODULES.keys())}")
    parser.add_argument("--threads", type=int, default=10, help="Concurrent threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=30, help="HTTP timeout seconds (default: 30)")
    parser.add_argument("--rate-limit", type=float, default=0.5, help="Seconds between requests (default: 0.5)")
    parser.add_argument("--top-ports", type=int, default=1000, help="Top N ports to scan (default: 1000)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose/debug logging")
    parser.add_argument("--list-modules", action="store_true", help="List modules and exit")
    parser.add_argument("-i", "--interactive", action="store_true", help="Interactive guided menu")
    parser.add_argument("--version", action="version", version=f"Recon Framework {__version__}")

    return parser.parse_args()


def list_modules():
    console.print()
    console.rule("[bold cyan]Available Modules[/bold cyan]")
    console.print()
    console.print("[bold blue]Passive:[/bold blue]")
    for name, cls in PASSIVE_MODULES.items():
        console.print(f"  [cyan]{name:14}[/cyan] [dim]{cls.description}[/dim]")
    console.print()
    console.print("[bold red]Active:[/bold red]")
    for name, cls in ACTIVE_MODULES.items():
        console.print(f"  [cyan]{name:14}[/cyan] [dim]{cls.description}[/dim]")
    console.print()
    console.print("[bold magenta]Analysis:[/bold magenta]")
    for name, cls in ALL_MODULES.items():
        if name not in PASSIVE_MODULES and name not in ACTIVE_MODULES:
            console.print(f"  [cyan]{name:14}[/cyan] [dim]{cls.description}[/dim]")
    console.print()


# ── Main ────────────────────────────────────────────────────────

def main():
    args = parse_args()

    # List modules
    if args.list_modules:
        print_banner()
        list_modules()
        sys.exit(0)

    # Interactive mode
    if args.interactive:
        cfg = interactive_menu()
        config = ScanConfig(
            target=cfg["target"],
            mode=cfg["mode"],
            output_dir=args.output or "",
            threads=cfg["threads"],
            timeout=args.timeout,
            rate_limit=args.rate_limit,
            port_scan_top=args.top_ports,
            verbose=cfg["verbose"],
            modules=cfg["modules"] or [],
        )
        _run(config)
        return

    # Direct CLI mode
    if not args.target and not args.targets:
        print_banner()
        console.print("[bold red]  Error:[/bold red] --target or --targets is required (or use -i for interactive mode)")
        console.print()
        sys.exit(1)

    modules = None
    if args.modules:
        modules = [m.strip() for m in args.modules.split(",")]
        invalid = [m for m in modules if m not in ALL_MODULES]
        if invalid:
            console.print(f"[bold red]Unknown modules:[/bold red] {', '.join(invalid)}")
            console.print(f"[dim]Available: {', '.join(ALL_MODULES.keys())}[/dim]")
            sys.exit(1)

    targets = []
    if args.targets:
        if not os.path.exists(args.targets):
            console.print(f"[bold red]File not found:[/bold red] {args.targets}")
            sys.exit(1)
        with open(args.targets) as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    else:
        targets = [args.target]

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
        _run(config)


def _run(config: ScanConfig):
    """Execute a scan with banner + timing."""
    print_banner()
    start = time.time()
    orchestrator = Orchestrator(config)
    try:
        asyncio.run(orchestrator.run())
    except KeyboardInterrupt:
        console.print("\n  [bold yellow]Interrupted by user.[/bold yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n  [bold red]Fatal error:[/bold red] {e}")
        if config.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    elapsed = time.time() - start
    console.print(f"  [dim]Completed in {elapsed:.1f}s[/dim]")
    console.print()


if __name__ == "__main__":
    main()
