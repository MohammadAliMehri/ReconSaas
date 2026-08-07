"""
Base module class for all recon modules.
"""
import abc
import logging
from typing import Any
from ..config import ScanConfig
from ..utils.logger import print_module_start


class BaseModule(abc.ABC):
    """Abstract base class for all recon modules."""

    name: str = "base"
    description: str = "Base module"
    mode: str = "both"  # passive | active | both

    def __init__(self, config: ScanConfig):
        self.config = config
        self.logger = logging.getLogger(f"recon.{self.name}")
        self.findings: list = []
        self.errors: list = []

    @abc.abstractmethod
    async def run(self, target: str) -> dict:
        """
        Execute the module against a target.
        
        Args:
            target: The target domain/URL
            
        Returns:
            dict with keys: findings, data, errors
        """
        pass

    async def execute(self, target: str) -> dict:
        """Execute with logging and error handling."""
        print_module_start(self.description, target)
        try:
            result = await self.run(target)
            self.logger.info(f"{self.name}: completed with {len(result.get('findings', []))} findings")
            return result
        except Exception as e:
            self.logger.error(f"{self.name}: failed — {e}")
            return {
                "module": self.name,
                "target": target,
                "findings": [],
                "data": {},
                "errors": [str(e)],
            }

    def add_finding(self, severity: str, title: str, detail: str = "", evidence: Any = None):
        """Add a finding to this module's results."""
        finding = {
            "severity": severity,
            "title": title,
            "detail": detail,
            "module": self.name,
            "evidence": evidence,
        }
        self.findings.append(finding)
        return finding

    def is_passive(self) -> bool:
        return self.mode in ("passive", "both")

    def is_active(self) -> bool:
        return self.mode in ("active", "both")
