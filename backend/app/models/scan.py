from sqlalchemy import Column, Integer, Float, String, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.database import Base
from datetime import datetime, timezone


class Scan(Base):
    __tablename__ = "scans"

    id              = Column(Integer, primary_key=True)
    ioc_id          = Column(Integer, ForeignKey("iocs.id"), nullable=False)
    timestamp       = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    composite_score = Column(Float, nullable=False)
    risk_level      = Column(String, nullable=False)
    raw_results     = Column(JSON)
    sources_queried = Column(JSON)
    error_sources   = Column(JSON, default=list)
    query_time_ms   = Column(Integer)

    ioc            = relationship("IOC", back_populates="scans")
    mitre_mappings = relationship("MITREMapping", back_populates="scan")


class MITREMapping(Base):
    __tablename__ = "mitre_mappings"

    id           = Column(Integer, primary_key=True)
    scan_id      = Column(Integer, ForeignKey("scans.id"), nullable=False)
    technique_id = Column(String)
    technique    = Column(String)
    tactic       = Column(String)
    confidence   = Column(String)
    source       = Column(String)

    scan = relationship("Scan", back_populates="mitre_mappings")
