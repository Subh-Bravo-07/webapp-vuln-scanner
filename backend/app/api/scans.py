import json
import time
import asyncio
from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_user_from_token
from app.core.target_validation import validate_target_is_safe
from app.db.session import get_db
from app.models.scan import ScanJob
from app.models.user import User
from app.schemas.scan import ScanCreate, ScanRead
from app.tasks.worker import run_scan_job

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
def create_scan(
    payload: ScanCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanJob:
    target_url = str(payload.target_url)
    try:
        validate_target_is_safe(target_url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if current_user.role != "admin":
        now = datetime.now(timezone.utc)
        day_start = datetime(now.year, now.month, now.day, tzinfo=timezone.utc).replace(tzinfo=None)
        used_today = (
            db.query(ScanJob)
            .filter(ScanJob.user_id == current_user.id, ScanJob.created_at >= day_start)
            .count()
        )
        if used_today >= current_user.daily_scan_quota:
            raise HTTPException(status_code=429, detail="Daily scan quota exceeded.")

    target_host = urlparse(target_url).hostname
    scope_urls = [str(url) for url in payload.in_scope_urls]
    for scope_url in scope_urls:
        scope_host = urlparse(scope_url).hostname
        if scope_host != target_host:
            raise HTTPException(
                status_code=400,
                detail="In-scope URLs must share the same hostname as the primary target.",
            )

    job = ScanJob(
        user_id=current_user.id,
        target_url=target_url,
        profile=payload.profile,
        authorization_confirmed=payload.authorization_confirmed,
        in_scope_urls_json=json.dumps(scope_urls),
        exclusions_json=json.dumps(payload.exclusions),
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    run_scan_job.delay(job.id)
    return job


@router.get("/{scan_id}", response_model=ScanRead)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanJob:
    job = (
        db.query(ScanJob)
        .filter(ScanJob.id == scan_id, ScanJob.user_id == current_user.id)
        .first()
    )
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    return job


@router.get("", response_model=list[ScanRead])
def list_scans(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ScanJob]:
    return (
        db.query(ScanJob)
        .filter(ScanJob.user_id == current_user.id)
        .order_by(ScanJob.created_at.desc())
        .all()
    )


@router.get("/{scan_id}/stream")
def stream_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> StreamingResponse:
    job = (
        db.query(ScanJob)
        .filter(ScanJob.id == scan_id, ScanJob.user_id == current_user.id)
        .first()
    )
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")

    def event_stream():
        terminal_statuses = {"completed", "failed"}
        while True:
            fresh = (
                db.query(ScanJob)
                .filter(ScanJob.id == scan_id, ScanJob.user_id == current_user.id)
                .first()
            )
            if not fresh:
                break
            payload = {
                "id": fresh.id,
                "status": fresh.status.value,
                "updated_at": fresh.updated_at.isoformat(),
            }
            yield f"data: {json.dumps(payload)}\n\n"
            if fresh.status.value in terminal_statuses:
                break
            time.sleep(2)

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@router.websocket("/ws/{scan_id}")
async def scan_ws(websocket: WebSocket, scan_id: int) -> None:
    await websocket.accept()
    token = websocket.query_params.get("token")
    if not token:
        await websocket.send_json({"error": "Missing token"})
        await websocket.close(code=1008)
        return

    db = next(get_db())
    try:
        user = get_user_from_token(token, db)
        job = (
            db.query(ScanJob)
            .filter(ScanJob.id == scan_id, ScanJob.user_id == user.id)
            .first()
        )
        if not job:
            await websocket.send_json({"error": "Scan not found"})
            await websocket.close(code=1008)
            return

        terminal_statuses = {"completed", "failed"}
        while True:
            fresh = (
                db.query(ScanJob)
                .filter(ScanJob.id == scan_id, ScanJob.user_id == user.id)
                .first()
            )
            if not fresh:
                break
            await websocket.send_json(
                {
                    "id": fresh.id,
                    "status": fresh.status.value,
                    "updated_at": fresh.updated_at.isoformat(),
                }
            )
            if fresh.status.value in terminal_statuses:
                break
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        return
    finally:
        db.close()
