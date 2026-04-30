import json

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, Response
from fpdf import FPDF
from sqlalchemy.orm import Session

from app.api.deps import get_current_user_optional, get_user_from_token
from app.db.session import get_db
from app.models.scan import ScanJob
from app.models.user import User

router = APIRouter(prefix="/reports", tags=["reports"])


def _severity_summary(findings: list[dict]) -> dict[str, int]:
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        sev = str(finding.get("severity", "info")).lower()
        if sev not in summary:
            sev = "info"
        summary[sev] += 1
    return summary


@router.get("/{scan_id}.json")
def get_report_json(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user_optional),
    token: str | None = Query(default=None),
) -> dict:
    if token:
        current_user = get_user_from_token(token, db)
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    job = (
        db.query(ScanJob)
        .filter(ScanJob.id == scan_id, ScanJob.user_id == current_user.id)
        .first()
    )
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = json.loads(job.findings_json or "[]")
    return {
        "scan_id": job.id,
        "target_url": job.target_url,
        "profile": job.profile,
        "status": job.status.value,
        "severity_summary": _severity_summary(findings),
        "findings": findings,
    }


@router.get("/{scan_id}.html", response_class=HTMLResponse)
def get_report_html(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user_optional),
    token: str | None = Query(default=None),
) -> str:
    if token:
        current_user = get_user_from_token(token, db)
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    job = (
        db.query(ScanJob)
        .filter(ScanJob.id == scan_id, ScanJob.user_id == current_user.id)
        .first()
    )
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = json.loads(job.findings_json or "[]")
    rows = []
    for finding in findings:
        rows.append(
            "<tr>"
            f"<td>{finding.get('module', '')}</td>"
            f"<td>{finding.get('title', '')}</td>"
            f"<td>{finding.get('severity', '')}</td>"
            f"<td>{finding.get('description', '')}</td>"
            "</tr>"
        )
    table_rows = "".join(rows) or "<tr><td colspan='4'>No findings.</td></tr>"
    return (
        "<html><head><title>Scan Report</title></head><body>"
        f"<h1>Scan Report #{job.id}</h1>"
        f"<p><strong>Target:</strong> {job.target_url}</p>"
        f"<p><strong>Profile:</strong> {job.profile}</p>"
        f"<p><strong>Status:</strong> {job.status.value}</p>"
        f"<p><strong>Severity Summary:</strong> {_severity_summary(findings)}</p>"
        "<table border='1' cellspacing='0' cellpadding='6'>"
        "<thead><tr><th>Module</th><th>Title</th><th>Severity</th><th>Description</th></tr></thead>"
        f"<tbody>{table_rows}</tbody>"
        "</table>"
        "</body></html>"
    )


@router.get("/{scan_id}.pdf")
def get_report_pdf(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user_optional),
    token: str | None = Query(default=None),
) -> Response:
    if token:
        current_user = get_user_from_token(token, db)
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    job = (
        db.query(ScanJob)
        .filter(ScanJob.id == scan_id, ScanJob.user_id == current_user.id)
        .first()
    )
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = json.loads(job.findings_json or "[]")
    summary = _severity_summary(findings)

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", size=14)
    pdf.cell(0, 10, txt=f"Scan Report #{job.id}", ln=1)
    pdf.set_font("Arial", size=11)
    pdf.cell(0, 8, txt=f"Target: {job.target_url}", ln=1)
    pdf.cell(0, 8, txt=f"Profile: {job.profile}", ln=1)
    pdf.cell(0, 8, txt=f"Status: {job.status.value}", ln=1)
    pdf.cell(0, 8, txt=f"Severity Summary: {summary}", ln=1)
    pdf.ln(4)
    for finding in findings[:30]:
        pdf.set_font("Arial", "B", size=10)
        pdf.multi_cell(0, 6, txt=f"[{finding.get('severity', 'info').upper()}] {finding.get('title', '')}")
        pdf.set_font("Arial", size=10)
        pdf.multi_cell(0, 6, txt=finding.get("description", ""))
        pdf.ln(1)
    pdf_bytes = bytes(pdf.output(dest="S"))
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"inline; filename=scan_report_{job.id}.pdf"},
    )
