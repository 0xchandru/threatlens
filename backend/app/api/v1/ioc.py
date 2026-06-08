from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from app.api.deps import get_db
from app.services.normalizer import detect_and_normalize
from app.services.aggregator import run_aggregation
from app.services.scorer import calculate_composite_score
from app.services.mitre import map_to_mitre
from app.services.enricher import run_enrichment
from app import crud

router = APIRouter(prefix="/ioc", tags=["ioc"])


@router.post("/lookup")
async def lookup_ioc(
    payload: dict,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    raw_value = payload.get("value", "").strip()
    if not raw_value:
        raise HTTPException(400, "IOC value is required")

    try:
        normalized = detect_and_normalize(raw_value)
    except ValueError as e:
        raise HTTPException(422, str(e))

    if normalized.is_private_ip():
        raise HTTPException(422, "Private IP addresses cannot be looked up")

    cached = crud.get_recent_scan(db, normalized.value, max_age_minutes=60)
    if cached:
        ioc = crud.get_ioc_by_value(db, normalized.value)
        mitre = [
            {
                "technique_id": m.technique_id,
                "technique":    m.technique,
                "tactic":       m.tactic,
                "confidence":   m.confidence,
                "source":       m.source,
            }
            for m in cached.mitre_mappings
        ]
        notes = crud.get_notes(db, ioc.id)
        tags  = crud.get_tags(db, ioc.id)
        return {
            "source":         "cache",
            "ioc":            {"value": ioc.value, "type": ioc.ioc_type, "id": ioc.id},
            "scan_id":        cached.id,
            "score":          cached.composite_score,
            "risk_level":     cached.risk_level,
            "confidence":     "high",
            "breakdown":      {},
            "mitre":          mitre,
            "results":        cached.raw_results or {},
            "errors":         cached.error_sources or [],
            "query_time_ms":  cached.query_time_ms or 0,
            "notes":          [{"id": n.id, "note": n.note, "analyst": n.analyst,
                                "created_at": n.created_at.isoformat()} for n in notes],
            "tags":           tags,
        }

    agg_result   = await run_aggregation(normalized.value, normalized.ioc_type)
    score_result = calculate_composite_score(agg_result["results"])
    mitre_techs  = map_to_mitre(agg_result["results"])

    ioc  = crud.get_or_create_ioc(db, normalized.value, normalized.ioc_type)
    scan = crud.create_scan(db, ioc, agg_result, score_result, mitre_techs)

    if normalized.ioc_type.value == "ip":
        background_tasks.add_task(run_enrichment, ioc.id, normalized.value, db)

    return {
        "source":        "live",
        "ioc":           {"value": ioc.value, "type": ioc.ioc_type, "id": ioc.id},
        "scan_id":       scan.id,
        "score":         score_result.composite_score,
        "risk_level":    score_result.risk_level,
        "confidence":    score_result.confidence,
        "breakdown":     score_result.score_breakdown,
        "mitre":         [vars(t) for t in mitre_techs],
        "results":       agg_result["results"],
        "errors":        agg_result["errors"],
        "query_time_ms": agg_result["query_time_ms"],
        "notes":         [],
        "tags":          [],
    }


@router.get("/{ioc_value}")
def get_ioc_detail(ioc_value: str, db: Session = Depends(get_db)):
    ioc = crud.get_ioc_by_value(db, ioc_value)
    if not ioc:
        raise HTTPException(404, "IOC not found")

    from app.models.scan import Scan
    from sqlalchemy import desc
    latest_scan = (
        db.query(Scan)
        .filter(Scan.ioc_id == ioc.id)
        .order_by(desc(Scan.timestamp))
        .first()
    )

    notes = crud.get_notes(db, ioc.id)
    tags  = crud.get_tags(db, ioc.id)

    return {
        "ioc":     {"value": ioc.value, "type": ioc.ioc_type, "id": ioc.id,
                    "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
                    "lookup_count": ioc.lookup_count},
        "latest_scan": {
            "score":     latest_scan.composite_score if latest_scan else None,
            "risk_level": latest_scan.risk_level if latest_scan else None,
            "timestamp": latest_scan.timestamp.isoformat() if latest_scan and latest_scan.timestamp else None,
            "results":   latest_scan.raw_results if latest_scan else {},
        } if latest_scan else None,
        "enrichment": {
            "asn":          ioc.enrichment.asn if ioc.enrichment else None,
            "asn_org":      ioc.enrichment.asn_org if ioc.enrichment else None,
            "country_code": ioc.enrichment.country_code if ioc.enrichment else None,
            "country_name": ioc.enrichment.country_name if ioc.enrichment else None,
            "city":         ioc.enrichment.city if ioc.enrichment else None,
            "rdns":         ioc.enrichment.rdns if ioc.enrichment else None,
        } if ioc.enrichment else None,
        "notes": [{"id": n.id, "note": n.note, "analyst": n.analyst,
                   "created_at": n.created_at.isoformat()} for n in notes],
        "tags":  tags,
    }


@router.get("/{ioc_value}/history")
def get_ioc_history(ioc_value: str, db: Session = Depends(get_db)):
    ioc = crud.get_ioc_by_value(db, ioc_value)
    if not ioc:
        raise HTTPException(404, "IOC not found")
    return crud.get_scan_history(db, ioc.id)


@router.post("/{ioc_value}/notes")
def add_note(ioc_value: str, payload: dict, db: Session = Depends(get_db)):
    ioc = crud.get_ioc_by_value(db, ioc_value)
    if not ioc:
        raise HTTPException(404, "IOC not found")
    note = crud.create_note(db, ioc.id, payload["note"], payload.get("analyst", "analyst"))
    return {"id": note.id, "note": note.note, "analyst": note.analyst,
            "created_at": note.created_at.isoformat()}


@router.delete("/{ioc_value}/notes/{note_id}")
def delete_note(ioc_value: str, note_id: int, db: Session = Depends(get_db)):
    ioc = crud.get_ioc_by_value(db, ioc_value)
    if not ioc:
        raise HTTPException(404, "IOC not found")
    if not crud.delete_note(db, note_id, ioc.id):
        raise HTTPException(404, "Note not found")
    return {"status": "deleted"}


@router.put("/{ioc_value}/tags")
def update_tags(ioc_value: str, payload: dict, db: Session = Depends(get_db)):
    ioc = crud.get_ioc_by_value(db, ioc_value)
    if not ioc:
        raise HTTPException(404, "IOC not found")
    crud.replace_tags(db, ioc.id, payload.get("tags", []))
    return {"status": "updated", "tags": payload["tags"]}
