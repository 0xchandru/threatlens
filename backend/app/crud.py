from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from datetime import datetime, timezone, timedelta
from app.models.ioc import IOC, IOCType
from app.models.scan import Scan, MITREMapping
from app.models.analyst import AnalystNote, ThreatTag, EnrichmentData
from app.models.report import Report


def get_ioc_by_value(db: Session, value: str):
    return db.query(IOC).filter(IOC.value == value).first()


def get_or_create_ioc(db: Session, value: str, ioc_type: IOCType) -> IOC:
    ioc = get_ioc_by_value(db, value)
    if ioc:
        ioc.lookup_count = (ioc.lookup_count or 0) + 1
        ioc.last_seen = datetime.now(timezone.utc)
        db.commit()
        db.refresh(ioc)
        return ioc
    ioc = IOC(value=value, ioc_type=ioc_type)
    db.add(ioc)
    db.commit()
    db.refresh(ioc)
    return ioc


def get_recent_scan(db: Session, value: str, max_age_minutes: int = 60):
    ioc = get_ioc_by_value(db, value)
    if not ioc:
        return None
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=max_age_minutes)
    scan = (
        db.query(Scan)
        .filter(Scan.ioc_id == ioc.id, Scan.timestamp >= cutoff)
        .order_by(desc(Scan.timestamp))
        .first()
    )
    return scan


def create_scan(db: Session, ioc: IOC, agg_result: dict, score_result, mitre_techniques: list) -> Scan:
    raw = agg_result.get("results", {})
    sources_queried = [k for k, v in raw.items() if v is not None]

    scan = Scan(
        ioc_id=ioc.id,
        composite_score=score_result.composite_score,
        risk_level=score_result.risk_level,
        raw_results=raw,
        sources_queried=sources_queried,
        error_sources=agg_result.get("errors", []),
        query_time_ms=agg_result.get("query_time_ms"),
    )
    db.add(scan)
    db.flush()

    for t in mitre_techniques:
        mapping = MITREMapping(
            scan_id=scan.id,
            technique_id=t.technique_id,
            technique=t.technique,
            tactic=t.tactic,
            confidence=t.confidence,
            source=t.source,
        )
        db.add(mapping)

    db.commit()
    db.refresh(scan)
    return scan


def get_scan_history(db: Session, ioc_id: int):
    scans = (
        db.query(Scan)
        .filter(Scan.ioc_id == ioc_id)
        .order_by(desc(Scan.timestamp))
        .limit(50)
        .all()
    )
    return [
        {
            "id":              s.id,
            "timestamp":       s.timestamp.isoformat() if s.timestamp else None,
            "composite_score": s.composite_score,
            "risk_level":      s.risk_level,
            "query_time_ms":   s.query_time_ms,
            "sources_queried": s.sources_queried,
        }
        for s in scans
    ]


def get_scan_detail(db: Session, scan_id: int):
    return db.query(Scan).filter(Scan.id == scan_id).first()


def create_note(db: Session, ioc_id: int, note: str, analyst: str = "analyst") -> AnalystNote:
    n = AnalystNote(ioc_id=ioc_id, note=note, analyst=analyst)
    db.add(n)
    db.commit()
    db.refresh(n)
    return n


def delete_note(db: Session, note_id: int, ioc_id: int) -> bool:
    n = db.query(AnalystNote).filter(AnalystNote.id == note_id, AnalystNote.ioc_id == ioc_id).first()
    if not n:
        return False
    db.delete(n)
    db.commit()
    return True


def get_notes(db: Session, ioc_id: int):
    return (
        db.query(AnalystNote)
        .filter(AnalystNote.ioc_id == ioc_id)
        .order_by(desc(AnalystNote.created_at))
        .all()
    )


def replace_tags(db: Session, ioc_id: int, tags: list[str]):
    db.query(ThreatTag).filter(ThreatTag.ioc_id == ioc_id).delete()
    for tag in tags:
        db.add(ThreatTag(ioc_id=ioc_id, tag=tag.strip().lower()))
    db.commit()


def get_tags(db: Session, ioc_id: int):
    return [t.tag for t in db.query(ThreatTag).filter(ThreatTag.ioc_id == ioc_id).all()]


def upsert_enrichment(db: Session, ioc_id: int, data: dict):
    existing = db.query(EnrichmentData).filter(EnrichmentData.ioc_id == ioc_id).first()
    if existing:
        for k, v in data.items():
            if hasattr(existing, k):
                setattr(existing, k, v)
        existing.enriched_at = datetime.now(timezone.utc)
    else:
        enrichment = EnrichmentData(ioc_id=ioc_id, **{
            k: v for k, v in data.items() if hasattr(EnrichmentData, k)
        })
        db.add(enrichment)
    db.commit()


def count_iocs(db: Session) -> int:
    return db.query(func.count(IOC.id)).scalar() or 0


def count_scans(db: Session) -> int:
    return db.query(func.count(Scan.id)).scalar() or 0


def count_scans_today(db: Session) -> int:
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    return db.query(func.count(Scan.id)).filter(Scan.timestamp >= today).scalar() or 0


def get_risk_distribution(db: Session) -> dict:
    rows = db.query(Scan.risk_level, func.count(Scan.id)).group_by(Scan.risk_level).all()
    return {row[0]: row[1] for row in rows}


def get_top_tags(db: Session, limit: int = 10):
    rows = (
        db.query(ThreatTag.tag, func.count(ThreatTag.id))
        .group_by(ThreatTag.tag)
        .order_by(desc(func.count(ThreatTag.id)))
        .limit(limit)
        .all()
    )
    return [{"tag": r[0], "count": r[1]} for r in rows]


def get_recent_by_risk(db: Session, risk_level: str, limit: int = 5):
    scans = (
        db.query(Scan)
        .filter(Scan.risk_level == risk_level)
        .order_by(desc(Scan.timestamp))
        .limit(limit)
        .all()
    )
    result = []
    for s in scans:
        ioc = db.query(IOC).filter(IOC.id == s.ioc_id).first()
        result.append({
            "ioc_value":       ioc.value if ioc else None,
            "ioc_type":        ioc.ioc_type if ioc else None,
            "composite_score": s.composite_score,
            "timestamp":       s.timestamp.isoformat() if s.timestamp else None,
        })
    return result


def get_ioc_type_counts(db: Session) -> dict:
    rows = db.query(IOC.ioc_type, func.count(IOC.id)).group_by(IOC.ioc_type).all()
    return {str(row[0]): row[1] for row in rows}


def get_avg_query_time(db: Session) -> float:
    avg = db.query(func.avg(Scan.query_time_ms)).scalar()
    return round(float(avg), 1) if avg else 0.0


def search_iocs(db: Session, tag: str = None, risk_level: str = None,
                ioc_type: str = None, limit: int = 50):
    query = db.query(IOC)
    if ioc_type:
        query = query.filter(IOC.ioc_type == ioc_type)
    if tag:
        query = query.join(ThreatTag).filter(ThreatTag.tag.ilike(f"%{tag}%"))
    if risk_level:
        query = query.join(Scan).filter(Scan.risk_level == risk_level)
    results = query.order_by(desc(IOC.last_seen)).limit(limit).all()
    return results


def get_timeline(db: Session, days: int = 30):
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    rows = (
        db.query(
            func.date(Scan.timestamp).label("date"),
            func.count(Scan.id).label("count")
        )
        .filter(Scan.timestamp >= cutoff)
        .group_by(func.date(Scan.timestamp))
        .order_by(func.date(Scan.timestamp))
        .all()
    )
    return [{"date": str(r.date), "count": r.count} for r in rows]


def save_report(db: Session, ioc_id: int, scan_id: int, filename: str, pdf_data: bytes) -> Report:
    report = Report(ioc_id=ioc_id, scan_id=scan_id, filename=filename, pdf_data=pdf_data)
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


def get_reports(db: Session, limit: int = 20):
    return db.query(Report).order_by(desc(Report.created_at)).limit(limit).all()


def get_report_by_id(db: Session, report_id: int):
    return db.query(Report).filter(Report.id == report_id).first()
