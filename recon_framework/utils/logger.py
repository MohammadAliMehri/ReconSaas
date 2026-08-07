"""
Logging and output management.
"""
import os
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

# Custom theme
THEME = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "passive": "blue",
    "active": "red",
    "hybrid": "magenta",
    "finding": "bold yellow",
    "target": "bold cyan",
    "module": "bold white",
})

console = Console(theme=THEME)


def setup_logging(output_dir: str, verbose: bool = False) -> logging.Logger:
    """Setup logging with file and console handlers."""
    os.makedirs(output_dir, exist_ok=True)
    
    logger = logging.getLogger("recon")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Console handler (rich)
    rich_handler = RichHandler(
        console=console,
        show_time=True,
        show_path=False,
        markup=True,
    )
    rich_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.addHandler(rich_handler)
    
    # File handler (UTF-8 to handle emoji safely)
    log_file = os.path.join(output_dir, "recon.log")
    file_handler = logging.FileHandler(log_file, mode="w", encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_fmt = logging.Formatter("%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s")
    file_handler.setFormatter(file_fmt)
    logger.addHandler(file_handler)
    
    return logger


def print_banner():
    """Print the tool banner."""
    banner = """
[bold cyan]
  ____  _____ ____  _   _ ______   _____ _____ _   _ ______ _____  
 |  _ \\| ____/ ___|| \\ | |  _ \\ \\ / /_ _|  ___| \\ | |  ____|  ___| 
 | |_) |  _|| |    |  \\| | | | \\ V / | || |_  |  \\| | |__  | |_    
 |  _ <| |__| |___ | |\\  | |_|  | |  | ||  _| | |\\  |  __| |  _|   
 |_| \\_\\_____\\____||_| \\_|____/  |_| |___|_|   |_| \\_|_|    |_|     
[/bold cyan]
[dim]  Zero-cost open-source reconnaissance framework[/dim]
[dim]  Passive | Active | Hybrid[/dim]
"""
    console.print(banner)


def print_mode_banner(mode: str):
    """Print mode-specific banner."""
    colors = {"passive": "blue", "active": "red", "hybrid": "magenta"}
    descriptions = {
        "passive": "No direct contact with target. Using OSINT, DNS, CT logs, search engines.",
        "active": "Direct authorized probing. Port scan, dir brute, header analysis, param fuzz.",
        "hybrid": "Passive expand first, then Active deep probe on ranked targets.",
    }
    color = colors.get(mode, "white")
    desc = descriptions.get(mode, "")
    
    panel = Panel(
        f"[{color}]{desc}[/{color}]",
        title=f"[bold {color}]{mode.upper()} MODE[/bold {color}]",
        border_style=color,
        box=box.DOUBLE,
    )
    console.print(panel)


def print_module_start(module_name: str, target: str):
    """Print module start message."""
    console.print(f"\n[module]▸ {module_name}[/module] → [target]{target}[/target]")


def print_finding(severity: str, title: str, detail: str = ""):
    """Print a finding with severity coloring."""
    severity_colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
        "info": "dim",
    }
    color = severity_colors.get(severity.lower(), "white")
    # Use ASCII-safe icons (no emoji — Windows charmap safe)
    icon = {"critical": "[!]", "high": "[!]", "medium": "[*]", "low": "[-]", "info": "[i]"}.get(severity.lower(), "[i]")
    console.print(f"  {icon} [{color}][{severity.upper()}][/{color}] {title}")
    if detail:
        console.print(f"    [dim]{detail}[/dim]")


def save_json(data: Any, path: str):
    """Save data as JSON."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def save_text(content: str, path: str):
    """Save text content to file."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


def print_summary_table(title: str, findings: list):
    """Print findings in a summary table."""
    table = Table(title=title, box=box.ROUNDED, show_lines=True)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Finding", style="white")
    table.add_column("Details", style="dim")
    
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get("severity", "info").lower(), 5))
    
    for f in sorted_findings:
        sev = f.get("severity", "info").upper()
        sev_style = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim"}.get(sev, "white")
        table.add_row(
            f"[{sev_style}]{sev}[/{sev_style}]",
            f.get("title", ""),
            f.get("detail", "")[:80],
        )
    
    console.print(table)
