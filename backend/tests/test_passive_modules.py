import httpx

from app.scanner.modules.csrf import CsrfTokenModule
from app.scanner.modules.fingerprinting import TechFingerprintingModule
from app.scanner.modules.sensitive_data import SensitiveDataExposureModule


def _response(
    body: str,
    headers: dict[str, str] | None = None,
    url: str = "https://example.com/",
) -> httpx.Response:
    request = httpx.Request("GET", url)
    return httpx.Response(200, headers=headers or {}, text=body, request=request)


def test_tech_fingerprinting_detects_headers_and_html_markers() -> None:
    module = TechFingerprintingModule()
    response = _response(
        '<html><head><meta name="generator" content="WordPress 6.4"></head>'
        "<body><script id=\"__NEXT_DATA__\"></script></body></html>",
        headers={"Server": "nginx", "X-Powered-By": "Express"},
    )

    fingerprints = module.analyze_response(response)

    assert {"type": "server", "value": "nginx", "detail": "Web server header exposed"} in fingerprints
    assert any(item["type"] == "x-powered-by" for item in fingerprints)
    assert any(item["type"] == "meta_generator" and item["value"] == "WordPress 6.4" for item in fingerprints)
    assert any(item["type"] == "html_marker" and item["value"] == "__NEXT_DATA__" for item in fingerprints)


def test_sensitive_data_exposure_redacts_detected_samples() -> None:
    module = SensitiveDataExposureModule()
    body = """
    window.config = {
      api_key: "super-secret-token-value",
      support: "security@example.com",
      jwt: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghiABCDEFGHI123456789"
    }
    """

    matches = module.analyze_body(body)

    assert {item["type"] for item in matches} >= {
        "email_address",
        "jwt_token",
        "generic_api_key_assignment",
    }
    assert all("super-secret-token-value" not in item["sample"] for item in matches)


def test_sensitive_data_exposure_scope_check_rejects_external_hosts() -> None:
    module = SensitiveDataExposureModule()

    assert module._same_host("https://example.com/app", "https://example.com") is True
    assert module._same_host("https://evil.example/app", "https://example.com") is False


def test_csrf_module_flags_state_changing_forms_without_token() -> None:
    module = CsrfTokenModule()
    html = """
    <form method="post" action="/profile">
      <input name="display_name" value="Alice">
    </form>
    <form method="post" action="/settings">
      <input name="csrf_token" value="abc123">
    </form>
    <form method="get" action="/search">
      <input name="q">
    </form>
    """

    missing = module.analyze_forms(html, "https://example.com/account")

    assert missing == [
        {
            "page_url": "https://example.com/account",
            "form_url": "https://example.com/profile",
            "method": "POST",
        }
    ]


def test_csrf_module_scope_and_exclusion_helpers() -> None:
    module = CsrfTokenModule()

    assert module._same_host("https://example.com/app", "https://example.com") is True
    assert module._same_host("https://cdn.example.com/app", "https://example.com") is False
    assert module._is_excluded("https://example.com/logout", ["/logout"]) is True
