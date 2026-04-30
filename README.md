# Multitool Webapp Vulnerability Scanner (MVP Foundation)

This repository contains a Phase-1 foundation for an authorized web vulnerability scanner platform.

## Important Legal/Ethical Notice

Only scan targets you own or have explicit written permission to test. Unauthorized scanning may be illegal.

## Implemented in this bootstrap

- FastAPI backend with initial scan APIs:
  - `POST /api/auth/register`
  - `POST /api/auth/login`
  - `POST /api/scans`
  - `GET /api/scans`
  - `GET /api/scans/{scan_id}`
  - `GET /api/scans/{scan_id}/stream`
  - `WS /api/scans/ws/{scan_id}?token=<jwt>`
- Report APIs:
  - `GET /api/reports/{scan_id}.json`
  - `GET /api/reports/{scan_id}.html`
  - `GET /api/reports/{scan_id}.pdf`
- Celery worker for asynchronous scan jobs.
- PostgreSQL persistence for scan jobs/results.
- Redis broker/backend for queueing.
- Modular scanner engine with initial passive checks:
  - Scope-aware crawler for endpoint discovery
  - Security headers analysis
  - Basic CORS misconfiguration detection
- Basic active checks in full/custom profile:
  - Reflected XSS reflection heuristic
  - Error-based SQLi signature heuristic
- Multitool orchestration scaffold:
  - External adapter execution for `nuclei`, `nikto`, `sqlmap` when installed
- Per-user ownership and token-based authentication for scan/report access.
- Role and quota support:
  - `admin` role bypasses quota
  - user daily scan quota enforcement
- Frontend UI:
  - **Vite + React + Tailwind** app in `frontend/`
  - Connects to the backend via `/api/*` (proxied to `http://localhost:8000` in dev) and WebSocket status updates
- Docker Compose for local development.

## Quick Start

### Backend (API + worker)

1. Start services:
   - `docker compose up --build`
2. Open API docs:
   - <http://localhost:8000/docs>

### Frontend (dashboard UI)

Prereqs:
- Node.js LTS (includes `npm`/`npx`)

Run the UI dev server:

```bash
cd frontend
npm install
npm run dev
```

Open:
- <http://localhost:5173>

Notes:
- The dev server proxies `/api/*` → `http://localhost:8000` (see `frontend/vite.config.ts`).

### API usage (optional)

Register:
- `POST /api/auth/register` with email/password

Login:
- `POST /api/auth/login` (OAuth2 form fields `username`, `password`)

Use returned bearer token:
- `Authorization: Bearer <access_token>`

Create a scan:
- `POST /api/scans` with:

```json
{
  "target_url": "https://example.com",
  "profile": "quick",
  "authorization_confirmed": true,
  "in_scope_urls": ["https://example.com/app"],
  "exclusions": ["/logout", "/admin/delete"]
}
```

Poll result:
- `GET /api/scans/{id}`

Open report links:
- `/api/reports/{id}.json`
- `/api/reports/{id}.html`
- `/api/reports/{id}.pdf`

## Suggested Next Steps

- Add authentication-aware crawling for logged-in application areas.
- Add PDF export and richer HTML report templates.
- Add org/team-level authorization workflows.
- Serve the built frontend (`frontend/dist`) from the backend or behind a reverse proxy (for a single origin in production).
- Expand external tool parsing into normalized finding objects.
