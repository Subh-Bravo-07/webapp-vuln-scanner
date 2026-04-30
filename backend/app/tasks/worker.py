import asyncio
import json

from celery import Celery
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import SessionLocal
from app.models.scan import ScanJob, ScanStatus
from app.scanner.engine import ScannerEngine

celery_app = Celery(
    "scanner_worker",
    broker=settings.broker_url,
    backend=settings.result_backend,
)


@celery_app.task(name="run_scan_job")
def run_scan_job(scan_id: int) -> None:
    db: Session = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if not job:
            return

        job.status = ScanStatus.running
        db.commit()

        engine = ScannerEngine()
        findings = asyncio.run(
            engine.run_profile(
                target_url=job.target_url,
                profile=job.profile,
                in_scope_urls=job.in_scope_urls,
                exclusions=job.exclusions,
            )
        )

        job.status = ScanStatus.completed
        job.findings_json = json.dumps([finding.model_dump() for finding in findings], indent=2)
        db.commit()
    except Exception as exc:  # noqa: BLE001
        job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if job:
            job.status = ScanStatus.failed
            job.error_message = str(exc)
            db.commit()
    finally:
        db.close()
