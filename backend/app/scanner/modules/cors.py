import httpx

from app.scanner.base import BaseModule
from app.schemas.scan import Finding


class CorsMisconfigModule(BaseModule):
    name = "cors_misconfiguration"

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
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            response = await client.get(target_url, headers={"Origin": "https://evil.example"})
        findings: list[Finding] = []
        acao = response.headers.get("Access-Control-Allow-Origin", "")
        acac = response.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*" and acac.lower() == "true":
            findings.append(
                Finding(
                    module=self.name,
                    title="Potentially dangerous CORS policy",
                    severity="high",
                    description=(
                        "Server allows wildcard origin while permitting credentials, "
                        "which is generally insecure."
                    ),
                    evidence={"acao": acao, "acac": acac, "url": str(response.url)},
                    remediation="Restrict allowed origins and avoid credentialed wildcard CORS.",
                )
            )
        return findings
