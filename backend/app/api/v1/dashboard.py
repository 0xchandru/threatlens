from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.api.deps import get_db
from app import crud

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    return {
        "total_iocs":         crud.count_iocs(db),
        "total_scans":        crud.count_scans(db),
        "scans_today":        crud.count_scans_today(db),
        "risk_distribution":  crud.get_risk_distribution(db),
        "top_tags":           crud.get_top_tags(db, limit=10),
        "recent_critical":    crud.get_recent_by_risk(db, "critical", limit=5),
        "ioc_type_breakdown": crud.get_ioc_type_counts(db),
        "avg_query_time_ms":  crud.get_avg_query_time(db),
    }


@router.get("/timeline")
def get_timeline(days: int = 30, db: Session = Depends(get_db)):
    return crud.get_timeline(db, days=days)
