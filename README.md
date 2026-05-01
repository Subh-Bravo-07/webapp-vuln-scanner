# 🔐 Multitool Web Application Vulnerability Scanner (MVP Foundation)

A modular, extensible **web vulnerability scanning platform** designed for authorized security testing. This repository provides a **Phase-1 foundation** for building a scalable, multi-engine security assessment tool with asynchronous processing and modern UI support.

---

## ⚠️ Legal & Ethical Disclaimer

This tool is intended **strictly for authorized security testing**.

* ✅ Only scan systems you **own** or have **explicit written permission** to test
* ❌ Unauthorized scanning may violate laws such as the IT Act, CFAA, or equivalent regulations
* ⚖️ You are solely responsible for how you use this software

---

## 🧩 Core Features

### 🚀 Backend (FastAPI)

* RESTful API with JWT-based authentication
* Scan lifecycle management
* Real-time scan updates via WebSocket
* Role-based access control and quota enforcement

#### 🔑 Authentication Endpoints

* `POST /api/auth/register` — Create account
* `POST /api/auth/login` — Obtain access token

#### 🛠 Scan Management

* `POST /api/scans` — Initiate a scan
* `GET /api/scans` — List user scans
* `GET /api/scans/{scan_id}` — Scan details
* `GET /api/scans/{scan_id}/stream` — Live scan updates
* `WS /api/scans/ws/{scan_id}?token=<jwt>` — WebSocket stream

#### 📊 Reports

* `GET /api/reports/{scan_id}.json`
* `GET /api/reports/{scan_id}.html`
* `GET /api/reports/{scan_id}.pdf`

---

### ⚙️ Asynchronous Processing

* **Celery worker** for background scan execution
* **Redis** as message broker & task backend
* Ensures non-blocking scan operations

---

### 🗄️ Persistence Layer

* **PostgreSQL** for:

  * Scan metadata
  * Results storage
  * User management

---

### 🔍 Scanner Engine (Modular Design)

#### 🧠 Passive Reconnaissance

* Scope-aware crawler (endpoint discovery)
* HTTP security headers analysis
* Basic CORS misconfiguration detection

#### ⚡ Active Testing (Profile-Based)

* Reflected XSS detection (heuristic-based)
* Error-based SQL Injection signatures

---

### 🔗 External Tool Integration (Multitool Orchestration)

Supports optional adapters for:

* `nuclei`
* `nikto`
* `sqlmap`

> Tools are executed only if installed and available in the environment.

---

### 👥 Access Control & Quotas

* Per-user scan ownership
* JWT-secured access to scans & reports
* Role system:

  * `admin` → unlimited scans
  * `user` → daily scan quota enforced

---

### 🖥 Frontend (Dashboard UI)

* Built with **Vite + React + Tailwind CSS**
* Features:

  * Scan creation & monitoring
  * Real-time updates via WebSocket
  * API integration via `/api/*`

---

### 🐳 Containerized Development

* Docker Compose setup for:

  * Backend API
  * Worker
  * Redis
  * PostgreSQL

---

## ⚡ Quick Start

### 🐳 Backend Setup

```bash
docker compose up --build
```

Access API docs:

```
http://localhost:8000/docs
```

---

### 💻 Frontend Setup

**Prerequisites:**

* Node.js (LTS)

```bash
cd frontend
npm install
npm run dev
```

Open:

```
http://localhost:5173
```

> Dev server proxies `/api/*` → `http://localhost:8000`

---

## 🔌 API Usage Example

### 📝 Register

```
POST /api/auth/register
```

### 🔐 Login

```
POST /api/auth/login
```

(OAuth2 form fields: `username`, `password`)

### 🪪 Authorization Header

```
Authorization: Bearer <access_token>
```

---

### ▶️ Create Scan

```json
{
  "target_url": "https://example.com",
  "profile": "quick",
  "authorization_confirmed": true,
  "in_scope_urls": ["https://example.com/app"],
  "exclusions": ["/logout", "/admin/delete"]
}
```

---

### 📡 Monitor Scan

```
GET /api/scans/{id}
```

---

### 📄 Retrieve Reports

* `/api/reports/{id}.json`
* `/api/reports/{id}.html`
* `/api/reports/{id}.pdf`

---

## 🧱 Architecture Overview

```
[ React Frontend ]
        ↓
[ FastAPI Backend ] ←→ [ PostgreSQL ]
        ↓
[ Celery Worker ] ←→ [ Redis ]
        ↓
[ Scanner Engine + External Tools ]
```

---

## 🚧 Roadmap / Next Steps

* 🔐 Authentication-aware crawling (session handling)
* 📄 Advanced reporting (PDF + rich HTML templates)
* 🏢 Organization/team-based access control
* 🌐 Production deployment (reverse proxy + unified origin)
* 🔄 Normalize findings from external tools into a unified schema
* 🧪 Add more vulnerability checks (SSRF, IDOR, CSP bypass, etc.)

---

## 🤝 Contribution Guidelines

Contributions are welcome. Please:

* Follow clean modular architecture
* Add tests where applicable
* Document new features clearly

---

## 📜 License

Specify your license here (e.g., MIT, Apache 2.0)

---

## 🛡️ Final Note

This project is a **foundation**, not a full-fledged scanner yet. It is designed to evolve into a **comprehensive, extensible cybersecurity platform**.

Build responsibly.
