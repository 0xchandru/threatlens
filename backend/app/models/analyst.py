from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from app.database import Base
from datetime import datetime, timezone


class AnalystNote(Base):
    __tablename__ = "analyst_notes"

    id         = Column(Integer, primary_key=True)
    ioc_id     = Column(Integer, ForeignKey("iocs.id"), nullable=False)
    note       = Column(Text, nullable=False)
    analyst    = Column(String, default="analyst")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    ioc = relationship("IOC", back_populates="notes")


class ThreatTag(Base):
    __tablename__ = "threat_tags"

    id         = Column(Integer, primary_key=True)
    ioc_id     = Column(Integer, ForeignKey("iocs.id"), nullable=False)
    tag        = Column(String, index=True)
    created_by = Column(String, default="analyst")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    ioc = relationship("IOC", back_populates="tags")


class EnrichmentData(Base):
    __tablename__ = "enrichment_data"

    id           = Column(Integer, primary_key=True)
    ioc_id       = Column(Integer, ForeignKey("iocs.id"), unique=True, nullable=False)
    asn          = Column(String)
    asn_org      = Column(String)
    country_code = Column(String)
    country_name = Column(String)
    city         = Column(String)
    whois_data   = Column(JSON)
    rdns         = Column(String)
    enriched_at  = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    ioc = relationship("IOC", back_populates="enrichment")
