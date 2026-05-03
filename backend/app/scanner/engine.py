import asyncio
from typing import Any

from app.scanner.modules.cors import CorsMisconfigModule
from app.scanner.modules.crawler import CrawlerModule
from app.scanner.modules.csrf import CsrfTokenModule
from app.scanner.modules.external_tools import ExternalToolsModule
from app.scanner.modules.fingerprinting import TechFingerprintingModule
from app.scanner.modules.headers import SecurityHeadersModule
from app.scanner.modules.sensitive_data import SensitiveDataExposureModule
from app.scanner.modules.sqli import BasicSQLiModule
from app.scanner.modules.xss import ReflectedXSSModule
from app.schemas.scan import Finding


class ScannerEngine:
    def __init__(self) -> None:
        self.crawler = CrawlerModule()
        self.passive_modules = [
            SecurityHeadersModule(),
            CorsMisconfigModule(),
            TechFingerprintingModule(),
            SensitiveDataExposureModule(),
            CsrfTokenModule(),
        ]
        self.active_modules = [ReflectedXSSModule(), BasicSQLiModule()]
        self.multitool_modules = [ExternalToolsModule()]

    @staticmethod
    def _extract_discovered_endpoints(findings: list[Finding]) -> list[str]:
        urls: list[str] = []
        for finding in findings:
            if finding.module != "crawler_discovery":
                continue
            evidence: dict[str, Any] = finding.evidence
            endpoints = evidence.get("endpoints", [])
            if isinstance(endpoints, list):
                urls.extend(str(item) for item in endpoints)
        return urls

    async def run_profile(
        self,
        target_url: str,
        profile: str,
        in_scope_urls: list[str] | None = None,
        exclusions: list[str] | None = None,
    ) -> list[Finding]:
        normalized_scope = in_scope_urls or []
        normalized_exclusions = exclusions or []
        crawler_findings = await self.crawler.run(
            target_url=target_url,
            in_scope_urls=normalized_scope,
            exclusions=normalized_exclusions,
        )
        discovered_endpoints = self._extract_discovered_endpoints(crawler_findings)

        modules = list(self.passive_modules)
        if profile == "full":
            modules.extend(self.active_modules)
            modules.extend(self.multitool_modules)
        elif profile == "custom":
            modules.extend(self.active_modules)
            modules.extend(self.multitool_modules)

        results = await asyncio.gather(
            *(
                module.run(
                    target_url=target_url,
                    in_scope_urls=normalized_scope,
                    exclusions=normalized_exclusions,
                    discovered_endpoints=discovered_endpoints,
                )
                for module in modules
            )
        )
        findings: list[Finding] = []
        findings.extend(crawler_findings)
        for module_findings in results:
            findings.extend(module_findings)
        return findings
