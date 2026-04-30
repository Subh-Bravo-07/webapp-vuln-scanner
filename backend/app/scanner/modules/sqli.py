from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx

from app.scanner.base import BaseModule
from app.schemas.scan import Finding


class BasicSQLiModule(BaseModule):
    name = "basic_sqli"
    payload = "'\")) OR 1=1--"
    error_signatures = [
        "sql syntax",
        "warning: mysql",
        "postgresql",
        "sqlite error",
        "unclosed quotation mark",
        "odbc sql server driver",
    ]

    def _inject_payload(self, url: str) -> str | None:
        parsed = urlparse(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        if not params:
            return None
        tampered = [(k, self.payload) for k, _ in params]
        return urlunparse(parsed._replace(query=urlencode(tampered)))

    async def run(
        self,
        target_url: str,
        in_scope_urls: list[str] | None = None,
        exclusions: list[str] | None = None,
        discovered_endpoints: list[str] | None = None,
    ) -> list[Finding]:
        _ = in_scope_urls
        _ = exclusions
        candidates = [target_url] + (discovered_endpoints or [])
        findings: list[Finding] = []
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            for candidate in candidates:
                attack_url = self._inject_payload(candidate)
                if not attack_url:
                    continue
                try:
                    response = await client.get(attack_url)
                except Exception:  # noqa: BLE001
                    continue
                body = response.text.lower()
                if any(sig in body for sig in self.error_signatures):
                    findings.append(
                        Finding(
                            module=self.name,
                            title="Potential SQL injection (error-based)",
                            severity="high",
                            description=(
                                "Database error signatures found after payload injection."
                            ),
                            evidence={"attack_url": attack_url, "status_code": response.status_code},
                            remediation=(
                                "Use parameterized queries and strict input validation."
                            ),
                        )
                    )
        return findings
