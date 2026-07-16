from datetime import datetime
from typing import Optional, List

from sqlalchemy import String, Integer, Boolean, Float, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from inform.core.database import Base


# ========================
# Credential Profiles
# ========================
class CredentialProfile(Base):
    """SNMPv3 credential profiles"""
    __tablename__ = "credential_profiles"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(200))

    username: Mapped[str] = mapped_column(String(50))
    auth_protocol: Mapped[str] = mapped_column(String(10))      # sha, md5, none
    auth_key: Mapped[str] = mapped_column(String(100))
    priv_protocol: Mapped[str] = mapped_column(String(10))      # aes, des, none
    priv_key: Mapped[str] = mapped_column(String(100))

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
    credential_profile_id: Mapped[Optional[int]] = mapped_column(ForeignKey("credential_profiles.id"))
    monitored: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(20), default="unknown")
    failure_count: Mapped[int] = mapped_column(Integer, default=0)
    response_time: Mapped[Optional[float]] = mapped_column(Float)
    last_checked: Mapped[Optional[datetime]] = mapped_column(DateTime)

    # Relationships
    credential_profile: Mapped[Optional["CredentialProfile"]] = relationship(back_populates="devices")


# ========================
# Discovery Jobs
# ========================
class DiscoveryJob(Base):
    """Subnet discovery jobs for automatic device discovery"""
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
# Users (for web login)
# ========================
class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(128), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
