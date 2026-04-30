from collections import deque
import re
from urllib.parse import urldefrag, urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from app.scanner.base import BaseModule
from app.schemas.scan import Finding


class CrawlerModule(BaseModule):
    name = "crawler_discovery"
    max_depth = 2
    max_pages = 25
    js_endpoint_pattern = re.compile(r"""['"](/[^"' ]+)['"]""")

    def _is_excluded(self, url: str, exclusions: list[str]) -> bool:
        return any(pattern and pattern in url for pattern in exclusions)

    def _in_scope(self, candidate_url: str, target_url: str, in_scope_urls: list[str]) -> bool:
        target_host = (urlparse(target_url).hostname or "").lower()
        candidate_host = (urlparse(candidate_url).hostname or "").lower()
        if candidate_host != target_host:
            return False
        if not in_scope_urls:
            return True
        return any(candidate_url.startswith(scope_url) for scope_url in in_scope_urls)

    async def run(
        self,
        target_url: str,
        in_scope_urls: list[str] | None = None,
        exclusions: list[str] | None = None,
        discovered_endpoints: list[str] | None = None,
    ) -> list[Finding]:
        _ = discovered_endpoints
        normalized_scope = [scope.rstrip("/") for scope in (in_scope_urls or [])]
        normalized_exclusions = exclusions or []
        queue: deque[tuple[str, int]] = deque([(target_url, 0)])
        seen: set[str] = set()
        discovered: list[str] = []
        forms: list[dict[str, str]] = []
        js_endpoints: list[str] = []

        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            while queue and len(discovered) < self.max_pages:
                current_url, depth = queue.popleft()
                if depth > self.max_depth or current_url in seen:
                    continue
                if self._is_excluded(current_url, normalized_exclusions):
                    continue
                if not self._in_scope(current_url, target_url, normalized_scope):
                    continue
                seen.add(current_url)

                try:
                    response = await client.get(current_url)
                except Exception:  # noqa: BLE001
                    continue

                content_type = response.headers.get("content-type", "")
                if "text/html" not in content_type:
                    continue

                discovered.append(str(response.url))
                soup = BeautifulSoup(response.text, "html.parser")
                for form in soup.find_all("form"):
                    action = form.get("action") or str(response.url)
                    method = (form.get("method") or "GET").upper()
                    form_url = urljoin(str(response.url), action)
                    forms.append({"url": form_url, "method": method})

                scripts = soup.find_all("script")
                for script in scripts:
                    src = script.get("src")
                    if src:
                        js_endpoints.append(urljoin(str(response.url), src))
                    if script.string:
                        for match in self.js_endpoint_pattern.findall(script.string):
                            js_endpoints.append(urljoin(str(response.url), match))

                for anchor in soup.find_all("a", href=True):
                    absolute = urljoin(str(response.url), anchor["href"])
                    clean_url = urldefrag(absolute).url
                    if clean_url not in seen:
                        queue.append((clean_url, depth + 1))

        if not discovered:
            return []

        return [
            Finding(
                module=self.name,
                title="Discovered endpoints in allowed scope",
                severity="info",
                description="Crawler discovered in-scope pages for downstream modules.",
                evidence={
                    "count": len(discovered),
                    "endpoints": discovered[:20],
                    "forms": forms[:20],
                    "js_endpoints": js_endpoints[:20],
                    "truncated": len(discovered) > 20,
                },
                remediation=(
                    "Review exposed endpoints and enforce least exposure for sensitive paths."
                ),
            )
        ]
