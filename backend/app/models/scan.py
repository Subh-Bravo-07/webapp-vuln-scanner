import enum
import json
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class ScanStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    profile: Mapped[str] = mapped_column(String(64), default="quick")
    authorization_confirmed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    in_scope_urls_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    exclusions_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.queued)
    findings_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    @property
    def in_scope_urls(self) -> list[str]:
        return json.loads(self.in_scope_urls_json or "[]")

    @property
    def exclusions(self) -> list[str]:
        return json.loads(self.exclusions_json or "[]")
