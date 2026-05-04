# HyperScan - Multitool Web Application Vulnerability Scanner

HyperScan is a modular web application vulnerability scanner for authorized security testing. It combines a FastAPI backend, Celery workers, Redis, PostgreSQL, and a React dashboard into a Phase-1 scanning platform that can grow into a broader OWASP-focused assessment tool.

This project is intentionally built as a foundation: it supports account-based scan ownership, scoped target submission, asynchronous scan jobs, live status updates, passive checks, basic active heuristics, optional external tool orchestration, and report exports.

## Legal And Ethical Use

Use this tool only on systems you own or have explicit written permission to test.

- Unauthorized scanning may violate laws such as the CFAA, IT Act, or equivalent local regulations.
- Users are responsible for scan targets, scope, timing, and authorization.
- The scanner includes target validation and quotas, but those controls do not replace legal permission.
- Do not use this project for exploitation, harassment, service disruption, or unauthorized reconnaissance.

## Current Features

### Backend

- FastAPI REST API with automatic OpenAPI docs.
- JWT authentication with register/login endpoints.
- Per-user scan ownership.
- Daily scan quotas for regular users.
- Admin role support for unlimited scan creation.
- Scan lifecycle tracking: queued, running, completed, failed.
- Celery worker execution with Redis broker/result backend.
- PostgreSQL persistence through SQLAlchemy models.
- Server-sent events and WebSocket scan status streaming.

### Frontend

- Vite + React + TypeScript dashboard.
- React production build served by FastAPI from the backend image.
- Tailwind CSS styling.
- Register/login form.
- Authorized target submission.
- Profile descriptions for quick, full, and custom scan modes.
- Visible module coverage for passive and full scan profiles.
- Scan history table.
- Scan details and raw JSON preview.
- In-dashboard findings view with severity summary, module, title, description, and remediation.
- WebSocket-based live scan status.
- Report links for JSON, HTML, and PDF exports.

The React dashboard is the single frontend source of truth. During Docker builds, `frontend/` is compiled with Vite and copied into the backend image so FastAPI can serve the same UI from `http://localhost:8000`.

### Scanner Engine

The engine runs a crawler first, extracts discovered in-scope endpoints, then dispatches passive or active modules depending on the selected scan profile.

Implemented modules:

- Scope-aware crawler with link discovery, form discovery, and basic JavaScript endpoint extraction.
- HTTP security header checks.
- CORS misconfiguration heuristic.
- Technology fingerprinting from response headers and HTML markers.
- Sensitive data exposure heuristic for emails, JWTs, AWS access key IDs, private key markers, and API-key-like assignments.
- Passive CSRF form heuristic for state-changing forms without recognizable CSRF token fields.
- Reflected XSS heuristic for query parameters.
- Error-based SQL injection signature heuristic.
- Optional external tool adapters for `nuclei`, `nikto`, and `sqlmap`.

### Scan Profiles

- `quick`: crawler + passive modules.
- `full`: crawler + passive modules + active heuristics + external tool adapters.
- `custom`: currently behaves like `full`; intended for future user-selected modules.

### Reports

- JSON report: `/api/reports/{scan_id}.json`
- HTML report: `/api/reports/{scan_id}.html`
- PDF report: `/api/reports/{scan_id}.pdf`

Reports include severity summary, scan metadata, findings, evidence, and remediation text. HTML report output escapes scanner-controlled content before rendering.

The frontend can also parse a loaded scan response and display findings directly in the dashboard, while keeping the raw JSON response available for troubleshooting.

## Architecture

```text
[ React Dashboard ]
        |
        v
[ FastAPI Backend ] <--> [ PostgreSQL ]
        |
        v
[ Celery Worker ] <--> [ Redis ]
        |
        v
[ Modular Scanner Engine ]
        |
        +--> Built-in modules
        +--> Optional external tools: nuclei, nikto, sqlmap
```

## Project Structure

```text
.
├── backend/
│   ├── app/
│   │   ├── api/              # Auth, scan, and report routes
│   │   ├── core/             # Config, security, target validation
│   │   ├── db/               # SQLAlchemy session/base
│   │   ├── models/           # User and scan models
│   │   ├── scanner/          # Engine and modules
│   │   ├── schemas/          # Pydantic request/response models
│   │   └── tasks/            # Celery worker task
│   ├── tests/
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── src/
│   ├── package.json
│   └── vite.config.ts
├── docker-compose.yml
└── README.md
```

## Quick Start

### Docker Compose

From the repository root:

```bash
docker compose up --build
```

Services:

- API: `http://localhost:8000`
- Backend-served dashboard: `http://localhost:8000`
- API docs: `http://localhost:8000/docs`
- PostgreSQL: `localhost:5432`
- Redis: `localhost:6379`

The API and worker read environment values from `backend/.env.example` in the current compose setup.

The Docker image builds the React dashboard from `frontend/` and copies `frontend/dist` into the backend image. For frontend development, use the Vite dev server below.

### Frontend Development Server

In a separate terminal:

```bash
cd frontend
npm install
npm run dev
```

Open:

```text
http://localhost:5173
```

The Vite dev server proxies `/api/*` requests to `http://localhost:8000`.

## API Examples

### Register

```http
POST /api/auth/register
Content-Type: application/json
```

```json
{
  "email": "user@example.com",
  "password": "change-me-securely"
}
```

### Login

```http
POST /api/auth/login
Content-Type: application/x-www-form-urlencoded
```

OAuth2 form fields:

```text
username=user@example.com
password=change-me-securely
```

Use the returned access token as:

```http
Authorization: Bearer <access_token>
```

### Create Scan

```http
POST /api/scans
Authorization: Bearer <access_token>
Content-Type: application/json
```

```json
{
  "target_url": "https://example.com",
  "profile": "quick",
  "authorization_confirmed": true,
  "in_scope_urls": ["https://example.com/app"],
  "exclusions": ["/logout", "/admin/delete"]
}
```

### List Scans

```http
GET /api/scans
Authorization: Bearer <access_token>
```

### Get Scan Details

```http
GET /api/scans/{scan_id}
Authorization: Bearer <access_token>
```

### Stream Scan Status

Server-sent events:

```http
GET /api/scans/{scan_id}/stream
Authorization: Bearer <access_token>
```

WebSocket:

```text
ws://localhost:8000/api/scans/ws/{scan_id}?token=<access_token>
```

### Retrieve Reports

```http
GET /api/reports/{scan_id}.json
GET /api/reports/{scan_id}.html
GET /api/reports/{scan_id}.pdf
```

Reports require either a bearer token or a `?token=<access_token>` query parameter.

## Target Validation And Scope Controls

The API requires `authorization_confirmed: true` before creating a scan.

Target validation blocks:

- Missing or invalid hostnames.
- `localhost`.
- `.local` hostnames.
- Targets resolving to private, loopback, link-local, multicast, reserved, or unspecified IP addresses.

In-scope URLs must share the same hostname as the primary target. Module-level checks also avoid cross-host discovered URLs.

## External Tools

The external tool module detects and runs supported tools only when they are installed in the worker environment.

Supported adapters:

- `nuclei`
- `nikto`
- `sqlmap`

Notes:

- Missing tools are reported as `not_installed`.
- `sqlmap` writes into a temporary per-run directory.
- External tool output is captured and truncated before being stored in findings.

## Development Checks

Backend syntax check:

```bash
cd backend
python -m compileall app tests
```

Backend tests:

```bash
cd backend
python -m pytest
```

Frontend type/build check:

```bash
cd frontend
npm run build
```

## Implemented Safety Hardening

- JWT-protected scan and report access.
- Per-user scan ownership checks.
- Daily user scan quotas.
- Target validation for common SSRF/local-network abuse paths.
- Same-host scope enforcement for submitted in-scope URLs.
- Escaped HTML report rendering.
- Temporary output directory for `sqlmap`.

## Roadmap

Near-term:

- ~~Target validation errors return clean API responses instead of 500s.~~
- ~~HTML report rendering escapes scanner-controlled content.~~
- ~~`sqlmap` writes to a temporary per-run output directory.~~
- ~~Backend Docker image serves the compiled React frontend.~~
- ~~Add passive technology fingerprinting.~~
- ~~Add passive sensitive data exposure heuristics.~~
- ~~Add passive CSRF form heuristics.~~
- ~~Show scan profile descriptions and module coverage in the dashboard.~~
- ~~Display loaded scan findings in the dashboard with severity summary and remediation.~~
- ~~Use the React dashboard as the single frontend source of truth.~~
- ~~Add focused unit tests for passive scanner module logic.~~
- Module selection for the `custom` profile.
- Better scan progress events with per-module status.
- Finding deduplication and stable finding IDs.
- Evidence drill-down in the dashboard findings table.
- Richer HTML report templates.
- Unit and integration tests around API routes and worker execution.
- `.gitignore` cleanup for Python cache files and generated reports.

Phase 2:

- Authentication-aware crawling with secure cookie/session handling.
- Playwright-based crawling for JavaScript-heavy apps.
- CSRF token validation improvements.
- CSP analysis.
- TLS checks.
- Technology-specific module recommendations.
- Safer external tool normalization into unified findings.

Phase 3:

- Plugin system for adding scanner modules.
- Nuclei template management.
- OWASP ZAP API integration.
- Batch scans and scheduled scans.
- GitHub/Jira issue export.
- Team/organization support.

## Limitations

- This is not a complete replacement for manual security testing.
- Passive heuristics may produce false positives.
- Active checks are intentionally basic and conservative.
- Authenticated area scanning is not implemented yet.
- JavaScript-heavy application crawling is limited until browser automation is added.
- External tools must be installed separately in the worker environment.

## Responsible Testing Targets

Use local intentionally vulnerable apps for development and validation, such as:

- OWASP Juice Shop
- DVWA
- bWAPP
- WebGoat

Only scan public systems when you have explicit written authorization.

## License

Add a project license before publishing or distributing this repository. Common choices include MIT, Apache-2.0, or GPL-3.0 depending on your goals.

## Final Note

HyperScan is a foundation for a careful, extensible, ethical vulnerability scanner. Build responsibly, test on authorized targets, and treat every finding as something that still deserves human review.
