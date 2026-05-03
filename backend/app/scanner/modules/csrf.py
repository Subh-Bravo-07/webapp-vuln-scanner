from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from app.scanner.base import BaseModule
from app.schemas.scan import Finding


class CsrfTokenModule(BaseModule):
    name = "csrf_token"
    max_urls = 10
    token_name_markers = ("csrf", "xsrf", "_token", "authenticity_token", "requestverificationtoken")
    state_changing_methods = {"POST", "PUT", "PATCH", "DELETE"}

    @staticmethod
    def _same_host(url: str, target_url: str) -> bool:
        return (urlparse(url).hostname or "").lower() == (
            urlparse(target_url).hostname or ""
        ).lower()

    @staticmethod
    def _is_excluded(url: str, exclusions: list[str]) -> bool:
        return any(pattern and pattern in url for pattern in exclusions)

    def _has_csrf_token(self, form) -> bool:
        for field in form.find_all(["input", "meta"]):
            name = str(field.get("name") or field.get("id") or "").lower()
            if any(marker in name for marker in self.token_name_markers):
                return True
        return False

    def analyze_forms(self, html: str, page_url: str) -> list[dict[str, str]]:
        soup = BeautifulSoup(html, "html.parser")
        missing_tokens: list[dict[str, str]] = []
        for form in soup.find_all("form"):
            method = str(form.get("method") or "GET").upper()
            if method not in self.state_changing_methods:
                continue
            if self._has_csrf_token(form):
                continue
            action = form.get("action") or page_url
            missing_tokens.append(
                {
                    "page_url": page_url,
                    "form_url": urljoin(page_url, action),
                    "method": method,
                }
            )
        return missing_tokens

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
            if self._same_host(url, target_url) and not self._is_excluded(url, normalized_exclusions)
        ][: self.max_urls]

        forms_missing_tokens: list[dict[str, str]] = []
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            for url in scoped_candidates:
                try:
                    response = await client.get(url)
                except Exception:  # noqa: BLE001
                    continue
                content_type = response.headers.get("content-type", "")
                if "text/html" not in content_type:
                    continue
                forms_missing_tokens.extend(self.analyze_forms(response.text, str(response.url)))

        if not forms_missing_tokens:
            return []

        return [
            Finding(
                module=self.name,
                title="State-changing forms missing visible CSRF tokens",
                severity="medium",
                description=(
                    "One or more state-changing forms did not include a recognizable CSRF token "
                    "field. This passive heuristic may need manual confirmation."
                ),
                evidence={
                    "checked_urls": len(scoped_candidates),
                    "forms_missing_tokens": forms_missing_tokens[:20],
                },
                remediation=(
                    "Add per-request anti-CSRF tokens to state-changing forms and validate them "
                    "server-side."
                ),
            )
        ]
