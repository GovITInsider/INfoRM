from datetime import datetime
from typing import Optional, List

from sqlalchemy import String, Integer, Boolean, Float, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from inform.core.database import Base

_BLANK_TOKENS = frozenset({"", "none", "null"})


def blank_to_none(value: str | None) -> str | None:
    """Empty / whitespace / the literal 'None' from Jinja → SQL NULL."""
    if value is None:
        return None
    text = str(value).strip()
    if text.lower() in _BLANK_TOKENS:
        return None
    return text


# ========================
# Credential Profiles
# ========================
class CredentialProfile(Base):
    """SNMP credential profiles (v1 / v2c / v3). Unused v3 fields store "" not NULL."""
    __tablename__ = "credential_profiles"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(200))

    snmp_version: Mapped[str] = mapped_column(String(10), default="v3", nullable=False)
    security_level: Mapped[str] = mapped_column(String(20), default="authPriv")
    community: Mapped[Optional[str]] = mapped_column(Text)

    username: Mapped[str] = mapped_column(String(50))
    auth_protocol: Mapped[str] = mapped_column(String(10))      # sha, md5, none
    auth_key: Mapped[str] = mapped_column(Text)
    priv_protocol: Mapped[str] = mapped_column(String(10))      # aes, des, none
    priv_key: Mapped[str] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    devices: Mapped[List["Device"]] = relationship(back_populates="credential_profile")


# ========================
# Buildings (Reference List)
# ========================
class Building(Base):
    """Reference list of valid building names"""
    __tablename__ = "buildings"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


# ========================
# Devices
# ========================
class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_tag: Mapped[Optional[str]] = mapped_column(String(50), unique=True, nullable=True)
    ip_address: Mapped[str] = mapped_column(String(45), unique=True, nullable=False)
    name: Mapped[Optional[str]] = mapped_column(String(100))
    building: Mapped[Optional[str]] = mapped_column(String(100))
    location: Mapped[Optional[str]] = mapped_column(String(100))
    comment: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    credential_profile_id: Mapped[Optional[int]] = mapped_column(ForeignKey("credential_profiles.id"))
    monitored: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(20), default="unknown")
    failure_count: Mapped[int] = mapped_column(Integer, default=0)
    response_time: Mapped[Optional[float]] = mapped_column(Float)
    last_checked: Mapped[Optional[datetime]] = mapped_column(DateTime)
    vendor: Mapped[Optional[str]] = mapped_column(String(100))
    model: Mapped[Optional[str]] = mapped_column(String(100))
    sys_object_id: Mapped[Optional[str]] = mapped_column(String(256))

    # Relationships
    credential_profile: Mapped[Optional["CredentialProfile"]] = relationship(back_populates="devices")


# ========================
# Discovery Jobs
# ========================
class DiscoveryJob(Base):
    """Unused. Scheduled subnet discovery is out of scope; do not add writers or a jobs UI."""
    __tablename__ = "discovery_jobs"

    id: Mapped[int] = mapped_column(primary_key=True)
    subnet: Mapped[str] = mapped_column(String(50), nullable=False)   # e.g. "10.50.0.0/24"
    credential_profile_id: Mapped[int] = mapped_column(ForeignKey("credential_profiles.id"))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run: Mapped[Optional[datetime]] = mapped_column(DateTime)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


# ========================
# Alarm Events (History)
# ========================
class AlarmEvent(Base):
    """Stores historical alarm and clear events"""
    __tablename__ = "alarm_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[Optional[int]] = mapped_column(ForeignKey("devices.id"))
    event_type: Mapped[str] = mapped_column(String(20))           # "ALARM" or "CLEARED"
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    failure_count: Mapped[int] = mapped_column(Integer, default=0)

    # Denormalized fields for easier display
    device_ip: Mapped[Optional[str]] = mapped_column(String(45))
    device_name: Mapped[Optional[str]] = mapped_column(String(100))
    building: Mapped[Optional[str]] = mapped_column(String(100))
    location: Mapped[Optional[str]] = mapped_column(String(100))


# ========================
# Scan sessions (on-demand Discover)
# ========================
class ScanSession(Base):
    __tablename__ = "scan_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    target: Mapped[str] = mapped_column(String(50), nullable=False)
    default_building: Mapped[Optional[str]] = mapped_column(String(100))
    profile_ids_json: Mapped[str] = mapped_column(Text, nullable=False)
    ping_timeout_seconds: Mapped[int] = mapped_column(Integer, default=1)
    ping_concurrency: Mapped[int] = mapped_column(Integer, default=32)
    snmp_timeout_seconds: Mapped[int] = mapped_column(Integer, default=2)
    snmp_concurrency: Mapped[int] = mapped_column(Integer, default=8)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    # pending|running|cancelling|completed|cancelled|failed
    total_hosts: Mapped[int] = mapped_column(Integer, default=0)
    pinged_count: Mapped[int] = mapped_column(Integer, default=0)
    live_count: Mapped[int] = mapped_column(Integer, default=0)
    snmp_done_count: Mapped[int] = mapped_column(Integer, default=0)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    timeout_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    error_message: Mapped[Optional[str]] = mapped_column(String(500))
    started_by: Mapped[Optional[str]] = mapped_column(String(50))
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime)


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Documentary FKs only — PRAGMA foreign_keys stays off.
    session_id: Mapped[int] = mapped_column(ForeignKey("scan_sessions.id"))
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    already_managed: Mapped[bool] = mapped_column(Boolean, default=False)
    managed_device_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL")
    )
    ping_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    ping_rtt_ms: Mapped[Optional[float]] = mapped_column(Float)
    snmp_status: Mapped[str] = mapped_column(String(20), default="skipped")
    # ok|auth_fail|no_snmp|skipped (managed)
    name: Mapped[Optional[str]] = mapped_column(String(100))
    location: Mapped[Optional[str]] = mapped_column(String(100))
    vendor: Mapped[Optional[str]] = mapped_column(String(100))
    model: Mapped[Optional[str]] = mapped_column(String(100))
    sys_object_id: Mapped[Optional[str]] = mapped_column(String(256))
    credential_profile_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("credential_profiles.id", ondelete="SET NULL")
    )


# ========================
# Users (for web login)
# ========================
class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(128), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
