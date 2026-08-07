"""
Orchestrator — Runs modules in the correct order for each mode.
"""
import asyncio
import logging
import os
from datetime import datetime
from typing import Optional

from .config import ScanConfig
from .utils.logger import (
    console, setup_logging, print_banner, print_mode_banner,
    print_finding, save_json, save_text, print_summary_table,
)
from .modules.dns_enum import DNSEnum
from .modules.cert_transparency import CertTransparency
from .modules.wayback_urls import WaybackURLs
from .modules.js_analyzer import JSAnalyzer
from .modules.port_scan import PortScanner
from .modules.tech_fingerprint import TechFingerprint
from .modules.header_analysis import HeaderAnalysis
from .modules.dir_bruteforce import DirBruteforce
from .modules.endpoint_probe import EndpointProbe
from .modules.bypass_403 import Bypass403
from .modules.asset_ranker import AssetRanker
from .modules.report_generator import ReportGenerator


# Module registry
PASSIVE_MODULES = {
    "dns": DNSEnum,
    "certs": CertTransparency,
    "wayback": WaybackURLs,
    "js": JSAnalyzer,
}

ACTIVE_MODULES = {
    "ports": PortScanner,
    "tech": TechFingerprint,
    "headers": HeaderAnalysis,
    "dirs": DirBruteforce,
    "endpoints": EndpointProbe,
    "bypass": Bypass403,
}

ANALYSIS_MODULES = {
    "rank": AssetRanker,
    "report": ReportGenerator,
}

ALL_MODULES = {**PASSIVE_MODULES, **ACTIVE_MODULES, **ANALYSIS_MODULES}


class Orchestrator:
    """Main orchestrator that runs modules based on mode."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.logger = logging.getLogger("recon.orchestrator")
        self.results = {
            "target": config.target,
            "mode": config.mode,
            "start_time": None,
            "end_time": None,
            "findings": [],
            "modules_run": [],
        }

    async def run(self):
        """Execute recon based on mode."""
        self.results["start_time"] = datetime.utcnow().isoformat()
        
        # Setup output directory
        os.makedirs(self.config.output_dir, exist_ok=True)
        setup_logging(self.config.output_dir, self.config.verbose)
        
        print_banner()
        print_mode_banner(self.config.mode)
        
        target = self.config.target.replace("https://", "").replace("http://", "").split("/")[0]
        
        # Determine which modules to run
        modules_to_run = self._get_modules()
        
        console.print(f"\n[info]Target:[/info] [target]{target}[/target]")
        console.print(f"[info]Mode:[/info] [{self.config.mode}]{self.config.mode}[/{self.config.mode}]")
        console.print(f"[info]Modules:[/info] {', '.join(modules_to_run)}")
        console.print(f"[info]Output:[/info] {self.config.output_dir}\n")
        
        # Phase 1: Passive recon
        if self.config.mode in ("passive", "hybrid"):
            console.rule("[bold blue]Phase 1: Passive Reconnaissance[/bold blue]")
            for name in modules_to_run:
                if name in PASSIVE_MODULES:
                    await self._run_module(name, target)

        # Phase 2: Active recon
        if self.config.mode in ("active", "hybrid"):
            console.rule("[bold red]Phase 2: Active Reconnaissance[/bold red]")
            for name in modules_to_run:
                if name in ACTIVE_MODULES:
                    await self._run_module(name, target)

        # Phase 3: Analysis
        console.rule("[bold magenta]Phase 3: Analysis & Reporting[/bold magenta]")
        
        # Run asset ranker
        ranker = AssetRanker(self.config)
        rank_result = await ranker.execute(self.results)
        self.results["asset_ranker"] = rank_result
        self.results["findings"].extend(rank_result.get("findings", []))
        
        # Save individual module results
        for name, data in self.results.items():
            if isinstance(data, dict) and "module" in data:
                subdir = "passive" if name in PASSIVE_MODULES else "active" if name in ACTIVE_MODULES else "analysis"
                path = os.path.join(self.config.output_dir, subdir, f"{name}.json")
                save_json(data, path)
        
        # Save subdomains list
        subdomains = self.results.get("cert_transparency", {}).get("data", {}).get("subdomains", [])
        if subdomains:
            save_text("\n".join(subdomains), os.path.join(self.config.output_dir, "passive", "subdomains.txt"))
        
        # Save URLs
        wayback = self.results.get("wayback_urls", {}).get("data", {}).get("urls", [])
        if wayback:
            save_text("\n".join(u.get("url", "") for u in wayback), os.path.join(self.config.output_dir, "passive", "wayback_urls.txt"))

        # Generate reports
        reporter = ReportGenerator(self.config)
        report_result = await reporter.execute(self.results)
        
        # Save markdown report
        md_content = report_result.get("data", {}).get("markdown", "")
        save_text(md_content, os.path.join(self.config.output_dir, "report.md"))
        
        # Save JSON report
        json_content = report_result.get("data", {}).get("json", {})
        save_json(json_content, os.path.join(self.config.output_dir, "report.json"))
        
        self.results["end_time"] = datetime.utcnow().isoformat()
        
        # Print summary
        self._print_summary()

    async def _run_module(self, name: str, target: str):
        """Run a single module."""
        module_class = ALL_MODULES.get(name)
        if not module_class:
            self.logger.warning(f"Module '{name}' not found")
            return
        
        # Check if module should run in current mode
        module = module_class(self.config)
        if self.config.mode == "passive" and not module.is_passive():
            return
        if self.config.mode == "active" and not module.is_active():
            return
        
        # Filter by user-specified modules
        if self.config.modules and name not in self.config.modules:
            return
        
        try:
            result = await module.execute(target)
            self.results[name] = result
            self.results["findings"].extend(result.get("findings", []))
            self.results["modules_run"].append(name)
            
            # Print findings
            for finding in result.get("findings", []):
                print_finding(
                    finding.get("severity", "info"),
                    finding.get("title", ""),
                    finding.get("detail", "")[:100],
                )
        except Exception as e:
            self.logger.error(f"Module {name} failed: {e}")

    def _get_modules(self) -> list:
        """Get list of modules to run based on mode and user selection."""
        if self.config.modules:
            return self.config.modules
        
        if self.config.mode == "passive":
            return list(PASSIVE_MODULES.keys())
        elif self.config.mode == "active":
            return list(ACTIVE_MODULES.keys())
        else:  # hybrid
            return list(PASSIVE_MODULES.keys()) + list(ACTIVE_MODULES.keys())

    def _print_summary(self):
        """Print final summary."""
        findings = self.results["findings"]
        
        console.print("\n")
        console.rule("[bold green]Recon Complete[/bold green]")
        
        # Summary table
        if findings:
            print_summary_table("All Findings", findings)
        
        # Stats
        console.print(f"\n[info]Modules run:[/info] {len(self.results['modules_run'])}")
        console.print(f"[info]Total findings:[/info] {len(findings)}")
        
        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        for sev, count in sorted(severity_counts.items()):
            color = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}.get(sev, "white")
            console.print(f"  [{color}]{sev.upper()}: {count}[/{color}]")
        
        console.print(f"\n[success]Report saved to:[/success] {self.config.output_dir}/report.md")
        console.print(f"[success]JSON data saved to:[/success] {self.config.output_dir}/report.json")
