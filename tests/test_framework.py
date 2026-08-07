"""
Tests for Recon Framework.
"""
import asyncio
import pytest
from recon_framework.config import ScanConfig
from recon_framework.utils.networking import extract_domain, extract_root_domain, is_valid_domain


class TestConfig:
    def test_from_target(self):
        config = ScanConfig.from_target("example.com")
        assert config.target == "https://example.com"
        assert config.mode == "hybrid"
    
    def test_from_target_with_http(self):
        config = ScanConfig.from_target("http://example.com")
        assert config.target == "http://example.com"
    
    def test_output_dir(self):
        config = ScanConfig.from_target("example.com")
        assert "recon-output" in config.output_dir
        assert "example.com" in config.output_dir


class TestNetworking:
    def test_extract_domain(self):
        assert extract_domain("https://www.example.com/path") == "www.example.com"
        assert extract_domain("http://sub.example.com") == "sub.example.com"
        assert extract_domain("example.com") == "example.com"
    
    def test_extract_root_domain(self):
        assert extract_root_domain("sub.example.com") == "example.com"
        assert extract_root_domain("deep.sub.example.com") == "example.com"
        assert extract_root_domain("example.com") == "example.com"
    
    def test_is_valid_domain(self):
        assert is_valid_domain("example.com") is True
        assert is_valid_domain("sub.example.com") is True
        assert is_valid_domain("not-a-domain") is False
        assert is_valid_domain("") is False


class TestModules:
    def test_module_imports(self):
        from recon_framework.modules.dns_enum import DNSEnum
        from recon_framework.modules.cert_transparency import CertTransparency
        from recon_framework.modules.wayback_urls import WaybackURLs
        from recon_framework.modules.js_analyzer import JSAnalyzer
        from recon_framework.modules.port_scan import PortScanner
        from recon_framework.modules.tech_fingerprint import TechFingerprint
        from recon_framework.modules.header_analysis import HeaderAnalysis
        from recon_framework.modules.dir_bruteforce import DirBruteforce
        from recon_framework.modules.endpoint_probe import EndpointProbe
        from recon_framework.modules.bypass_403 import Bypass403
        from recon_framework.modules.asset_ranker import AssetRanker
        from recon_framework.modules.report_generator import ReportGenerator
        
        for cls in [DNSEnum, CertTransparency, WaybackURLs, JSAnalyzer,
                     PortScanner, TechFingerprint, HeaderAnalysis,
                     DirBruteforce, EndpointProbe, Bypass403,
                     AssetRanker, ReportGenerator]:
            assert hasattr(cls, 'name')
            assert hasattr(cls, 'description')
            assert hasattr(cls, 'mode')
            assert hasattr(cls, 'run')
    
    def test_module_modes(self):
        from recon_framework.modules.dns_enum import DNSEnum
        from recon_framework.modules.port_scan import PortScanner
        
        config = ScanConfig.from_target("example.com")
        
        dns = DNSEnum(config)
        assert dns.is_passive() is True
        assert dns.is_active() is False
        
        port = PortScanner(config)
        assert port.is_passive() is False
        assert port.is_active() is True


class TestCLI:
    def test_cli_import(self):
        from recon_framework.cli import main, parse_args
        assert callable(main)
    
    def test_orchestrator_import(self):
        from recon_framework.orchestrator import Orchestrator, PASSIVE_MODULES, ACTIVE_MODULES
        assert len(PASSIVE_MODULES) > 0
        assert len(ACTIVE_MODULES) > 0


class TestFingerprintEngine:
    def test_engine_loads(self):
        from recon_framework.utils.fingerprints import FINGERPRINTS, CATEGORIES
        assert len(FINGERPRINTS) >= 200
        assert len(CATEGORIES) >= 40
    
    def test_engine_matching(self):
        from recon_framework.utils.engine import FingerprintEngine
        eng = FingerprintEngine()
        matches = eng.analyze(
            headers={"Server": "nginx/1.24.0", "X-Powered-By": "PHP/8.2.10", "CF-RAY": "abc"},
            cookies=["PHPSESSID", "__cf_bm"],
            body='<meta name="generator" content="WordPress 6.5">',
            script_sources=["https://example.com/wp-includes/js/jquery.min.js"],
        )
        names = [m.name for m in matches]
        assert "Nginx" in names
        assert "PHP" in names
        assert "WordPress" in names
        assert "Cloudflare" in names
        assert "jQuery" in names
    
    def test_version_extraction(self):
        from recon_framework.utils.engine import FingerprintEngine
        eng = FingerprintEngine()
        matches = eng.analyze(headers={"Server": "nginx/1.24.0", "X-Powered-By": "PHP/8.2.10"})
        nginx = next(m for m in matches if m.name == "Nginx")
        assert nginx.version == "1.24.0"
        php = next(m for m in matches if m.name == "PHP")
        assert php.version == "8.2.10"
    
    def test_no_false_positive_django(self):
        from recon_framework.utils.engine import FingerprintEngine
        eng = FingerprintEngine()
        matches = eng.analyze(
            headers={"X-Frame-Options": "DENY", "Server": "nginx"},
            cookies=["XSRF-TOKEN"],
        )
        names = [m.name for m in matches]
        assert "Django" not in names


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
