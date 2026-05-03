import re

import httpx

from app.scanner.base import BaseModule
from app.schemas.scan import Finding


class TechFingerprintingModule(BaseModule):
    name = "tech_fingerprinting"

    header_markers = {
        "server": "Web server header exposed",
        "x-powered-by": "Application framework header exposed",
        "x-generator": "CMS or site generator header exposed",
        "x-aspnet-version": "ASP.NET version header exposed",
    }
    html_markers = {
        "wp-content": "WordPress asset path detected",
        "wp-includes": "WordPress asset path detected",
        "drupal-settings-json": "Drupal settings marker detected",
        "content=\"joomla": "Joomla generator marker detected",
        "reactroot": "React application marker detected",
        "__NEXT_DATA__": "Next.js data marker detected",
    }
    generator_pattern = re.compile(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
        re.IGNORECASE,
    )

    @staticmethod
    def _dedupe(items: list[dict[str, str]]) -> list[dict[str, str]]:
        seen: set[tuple[str, str]] = set()
        deduped: list[dict[str, str]] = []
        for item in items:
            key = (item["type"], item["value"])
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)
        return deduped

    def analyze_response(self, response: httpx.Response) -> list[dict[str, str]]:
        fingerprints: list[dict[str, str]] = []
        lower_headers = {key.lower(): value for key, value in response.headers.items()}
        for header, label in self.header_markers.items():
            value = lower_headers.get(header)
            if value:
                fingerprints.append({"type": header, "value": value[:120], "detail": label})

        body = response.text[:200_000]
        lower_body = body.lower()
        for marker, label in self.html_markers.items():
            if marker.lower() in lower_body:
                fingerprints.append({"type": "html_marker", "value": marker, "detail": label})

        generator = self.generator_pattern.search(body)
        if generator:
            fingerprints.append(
                {
                    "type": "meta_generator",
                    "value": generator.group(1)[:120],
                    "detail": "HTML generator metadata detected",
                }
            )
        return self._dedupe(fingerprints)

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
        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                response = await client.get(target_url)
        except Exception:  # noqa: BLE001
            return []

        fingerprints = self.analyze_response(response)
        if not fingerprints:
            return []

        return [
            Finding(
                module=self.name,
                title="Technology fingerprints detected",
                severity="info",
                description=(
                    "Response metadata and page markers reveal technology details that can help "
                    "attackers tailor follow-up testing."
                ),
                evidence={"url": str(response.url), "fingerprints": fingerprints[:20]},
                remediation=(
                    "Remove unnecessary version banners and generator metadata where practical."
                ),
            )
        ]
