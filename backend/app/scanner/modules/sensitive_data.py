import re
from urllib.parse import urlparse

import httpx

from app.scanner.base import BaseModule
from app.schemas.scan import Finding


class SensitiveDataExposureModule(BaseModule):
    name = "sensitive_data_exposure"
    max_urls = 10
    max_body_chars = 250_000
    patterns = {
        "email_address": re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
        ),
        "jwt_token": re.compile(
            r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
        ),
        "aws_access_key_id": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "private_key_marker": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "generic_api_key_assignment": re.compile(
            r"(?i)\b(api[_-]?key|secret|token)\b\s*[:=]\s*['\"][^'\"]{12,}['\"]"
        ),
    }

    @staticmethod
    def _same_host(url: str, target_url: str) -> bool:
        return (urlparse(url).hostname or "").lower() == (
            urlparse(target_url).hostname or ""
        ).lower()

    @staticmethod
    def _redact(value: str) -> str:
        if len(value) <= 12:
            return "*" * len(value)
        return f"{value[:6]}...{value[-4:]}"

    def analyze_body(self, body: str) -> list[dict[str, str]]:
        findings: list[dict[str, str]] = []
        searchable = body[: self.max_body_chars]
        for pattern_name, pattern in self.patterns.items():
            for match in pattern.finditer(searchable):
                findings.append(
                    {
                        "type": pattern_name,
                        "sample": self._redact(match.group(0).replace("\n", "\\n")),
                    }
                )
                break
        return findings

    async def run(
        self,
        target_url: str,
        in_scope_urls: list[str] | None = None,
        exclusions: list[str] | None = None,
        discovered_endpoints: list[str] | None = None,
    ) -> list[Finding]:
        _ = in_scope_urls
        normalized_exclusions = exclusions or []
        candidates = [target_url] + (discovered_endpoints or [])
        scoped_candidates = [
            url
            for url in dict.fromkeys(candidates)
            if self._same_host(url, target_url)
            and not any(pattern and pattern in url for pattern in normalized_exclusions)
        ][: self.max_urls]

        exposures: list[dict[str, object]] = []
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            for url in scoped_candidates:
                try:
                    response = await client.get(url)
                except Exception:  # noqa: BLE001
                    continue
                content_type = response.headers.get("content-type", "")
                if not any(kind in content_type for kind in ("text/", "json", "javascript")):
                    continue
                matches = self.analyze_body(response.text)
                if matches:
                    exposures.append(
                        {
                            "url": str(response.url),
                            "status_code": response.status_code,
                            "matches": matches,
                        }
                    )

        if not exposures:
            return []

        return [
            Finding(
                module=self.name,
                title="Potential sensitive data exposure",
                severity="medium",
                description=(
                    "Publicly reachable responses appear to contain sensitive identifiers, "
                    "tokens, keys, or contact data."
                ),
                evidence={"checked_urls": len(scoped_candidates), "exposures": exposures[:20]},
                remediation=(
                    "Remove secrets from client responses, rotate exposed credentials, and keep "
                    "only intentional public contact data in rendered pages."
                ),
            )
        ]
