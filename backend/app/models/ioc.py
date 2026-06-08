from sqlalchemy import Column, String, Integer, DateTime, Float, Enum
from sqlalchemy.orm import relationship
from app.database import Base
from datetime import datetime, timezone
import enum


class IOCType(str, enum.Enum):
    ip     = "ip"
    domain = "domain"
    url    = "url"
    md5    = "md5"
    sha1   = "sha1"
    sha256 = "sha256"


class IOC(Base):
    __tablename__ = "iocs"

    id           = Column(Integer, primary_key=True, index=True)
    value        = Column(String, unique=True, index=True, nullable=False)
    ioc_type     = Column(Enum(IOCType), nullable=False)
    first_seen   = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen    = Column(DateTime, onupdate=lambda: datetime.now(timezone.utc))
    lookup_count = Column(Integer, default=1)

    scans      = relationship("Scan", back_populates="ioc")
    notes      = relationship("AnalystNote", back_populates="ioc")
    tags       = relationship("ThreatTag", back_populates="ioc")
    enrichment = relationship("EnrichmentData", back_populates="ioc", uselist=False)
