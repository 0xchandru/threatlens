from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, LargeBinary
from sqlalchemy.orm import relationship
from app.database import Base
from datetime import datetime, timezone


class Report(Base):
    __tablename__ = "reports"

    id         = Column(Integer, primary_key=True)
    ioc_id     = Column(Integer, ForeignKey("iocs.id"), nullable=False)
    scan_id    = Column(Integer, ForeignKey("scans.id"), nullable=False)
    filename   = Column(String, nullable=False)
    pdf_data   = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    created_by = Column(String, default="analyst")
