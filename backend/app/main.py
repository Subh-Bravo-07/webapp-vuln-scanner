from pathlib import Path

from app.api.auth import router as auth_router
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api.reports import router as reports_router
from app.api.scans import router as scans_router
from app.core.config import settings
from app.db.session import Base, engine
from app.models.scan import ScanJob  # noqa: F401
from app.models.user import User  # noqa: F401

app = FastAPI(title=settings.app_name, version="0.1.0")

# MVP convenience: create tables on startup.
Base.metadata.create_all(bind=engine)

app.include_router(auth_router, prefix="/api")
app.include_router(scans_router, prefix="/api")
app.include_router(reports_router, prefix="/api")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}

backend_root = Path(__file__).resolve().parents[1]
repo_root = backend_root.parent
frontend_dir = backend_root / "frontend"
local_dist_dir = repo_root / "frontend" / "dist"

static_frontend_dir = frontend_dir if (frontend_dir / "index.html").exists() else local_dist_dir
if (static_frontend_dir / "index.html").exists():
    app.mount("/", StaticFiles(directory=static_frontend_dir, html=True), name="frontend")
