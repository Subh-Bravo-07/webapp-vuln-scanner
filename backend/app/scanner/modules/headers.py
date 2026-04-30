import httpx

from app.scanner.base import BaseModule
from app.schemas.scan import Finding


class SecurityHeadersModule(BaseModule):
    name = "security_headers"
    required_headers = {
        "x-frame-options": "Add X-Frame-Options to defend against clickjacking.",
        "content-security-policy": "Set a strict Content-Security-Policy.",
        "x-content-type-options": "Set X-Content-Type-Options: nosniff.",
        "strict-transport-security": "Set HSTS on HTTPS responses.",
    }

    async def run(
        self,
        target_url: str,
        in_scope_urls: list[str] | None = None,
        exclusions: list[str] | None = None,
        discovered_endpoints: list[str] | None = None,
    ) -> list[Finding]:
        _ = in_scope_urls
        _ = exclusions
        _ = discovered_endpoints
        findings: list[Finding] = []
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            response = await client.get(target_url)
        headers = {k.lower(): v for k, v in response.headers.items()}
        for header, remediation in self.required_headers.items():
            if header not in headers:
                findings.append(
                    Finding(
                        module=self.name,
                        title=f"Missing header: {header}",
                        severity="medium",
                        description=f"The response is missing {header}.",
                        evidence={"url": str(response.url), "status_code": response.status_code},
                        remediation=remediation,
                    )
                )
        return findings
