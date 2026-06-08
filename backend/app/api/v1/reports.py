from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session
from app.api.deps import get_db
from app.services.pdf_generator import generate_ioc_report
from app import crud
import datetime

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post("/generate")
def generate_report(payload: dict, db: Session = Depends(get_db)):
    ioc_value = payload.get("ioc_value")
    scan_id   = payload.get("scan_id")

    if not ioc_value:
        raise HTTPException(400, "ioc_value is required")

    ioc = crud.get_ioc_by_value(db, ioc_value)
    if not ioc:
        raise HTTPException(404, "IOC not found")

    if scan_id:
        scan = crud.get_scan_detail(db, scan_id)
    else:
        from app.models.scan import Scan
        from sqlalchemy import desc
        scan = (
            db.query(Scan)
            .filter(Scan.ioc_id == ioc.id)
            .order_by(desc(Scan.timestamp))
            .first()
        )

    if not scan:
        raise HTTPException(404, "No scan found for this IOC")

    notes = crud.get_notes(db, ioc.id)
    mitre = [
        {
            "technique_id": m.technique_id,
            "technique":    m.technique,
            "tactic":       m.tactic,
            "confidence":   m.confidence,
            "source":       m.source,
        }
        for m in scan.mitre_mappings
    ]

    scan_data = {
        "ioc":           {"value": ioc.value, "type": str(ioc.ioc_type)},
        "score":         scan.composite_score,
        "risk_level":    scan.risk_level,
        "confidence":    "high",
        "query_time_ms": scan.query_time_ms or 0,
        "breakdown":     {},
    }

    notes_data = [
        {"analyst": n.analyst, "note": n.note, "created_at": n.created_at.isoformat()}
        for n in notes
    ]

    pdf_bytes = generate_ioc_report(scan_data, notes_data, mitre)

    timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename  = f"threatlens_{ioc_value.replace('/', '_')}_{timestamp}.pdf"

    report = crud.save_report(db, ioc.id, scan.id, filename, pdf_bytes)
    return {"id": report.id, "filename": report.filename, "created_at": report.created_at.isoformat()}


@router.get("")
def list_reports(db: Session = Depends(get_db)):
    reports = crud.get_reports(db)
    return [
        {
            "id":         r.id,
            "filename":   r.filename,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in reports
    ]


@router.get("/{report_id}/download")
def download_report(report_id: int, db: Session = Depends(get_db)):
    report = crud.get_report_by_id(db, report_id)
    if not report:
        raise HTTPException(404, "Report not found")
    return Response(
        content=report.pdf_data,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{report.filename}"'},
    )
