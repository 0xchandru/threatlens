from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from app.api.deps import get_db
from app import crud

router = APIRouter(prefix="/search", tags=["search"])


@router.get("")
def search_iocs(
    tag:        str = Query(None),
    risk_level: str = Query(None),
    ioc_type:   str = Query(None),
    limit:      int = Query(50, le=200),
    db: Session = Depends(get_db),
):
    results = crud.search_iocs(db, tag=tag, risk_level=risk_level, ioc_type=ioc_type, limit=limit)
    return [
        {
            "id":           ioc.id,
            "value":        ioc.value,
            "ioc_type":     ioc.ioc_type,
            "first_seen":   ioc.first_seen.isoformat() if ioc.first_seen else None,
            "last_seen":    ioc.last_seen.isoformat() if ioc.last_seen else None,
            "lookup_count": ioc.lookup_count,
        }
        for ioc in results
    ]
