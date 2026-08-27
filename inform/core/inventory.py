"""Export/import buildings and devices as a YAML inventory file."""

from __future__ import annotations

from typing import Any

import yaml
from sqlalchemy.orm import Session

from inform.core.models import Building, CredentialProfile, Device, blank_to_none

INVENTORY_VERSION = 2
SUPPORTED_INVENTORY_VERSIONS = {1, 2}


def build_inventory(db: Session) -> dict[str, Any]:
    buildings = db.query(Building).order_by(Building.name).all()
    devices = db.query(Device).order_by(Device.ip_address).all()
    profile_names = {p.id: p.name for p in db.query(CredentialProfile).all()}
    return {
        "version": INVENTORY_VERSION,
        "buildings": [
            {
                "name": b.name,
                "description": b.description or "",
            }
            for b in buildings
        ],
        "devices": [
            {
                "ip_address": d.ip_address,
                "asset_tag": d.asset_tag or "",
                "name": d.name or "",
                "building": d.building or "",
                "location": d.location or "",
                "comment": d.comment or "",
                "monitored": bool(d.monitored),
                "vendor": d.vendor or "",
                "model": d.model or "",
                "credential_profile": profile_names.get(d.credential_profile_id, "")
                if d.credential_profile_id
                else "",
                # sys_object_id is an internal refresh cache; omit from backups
            }
            for d in devices
        ],
    }


def dump_inventory_yaml(inventory: dict[str, Any]) -> str:
    return yaml.safe_dump(
        inventory,
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
    )


def load_inventory_yaml(text: str) -> dict[str, Any]:
    raw = yaml.safe_load(text) or {}
    if not isinstance(raw, dict):
        raise ValueError("Inventory file must be a YAML mapping with buildings and devices lists.")

    if "version" in raw and raw["version"] not in SUPPORTED_INVENTORY_VERSIONS:
        raise ValueError(
            f"Unsupported inventory version {raw['version']!r}. Expected 1 or 2."
        )

    buildings = raw.get("buildings") or []
    devices = raw.get("devices") or []
    if not isinstance(buildings, list) or not isinstance(devices, list):
        raise ValueError("'buildings' and 'devices' must be YAML lists.")

    cleaned_buildings = []
    for i, item in enumerate(buildings, start=1):
        if not isinstance(item, dict) or not str(item.get("name") or "").strip():
            raise ValueError(f"Building #{i} is missing a name.")
        cleaned_buildings.append({
            "name": str(item["name"]).strip(),
            "description": str(item.get("description") or "").strip(),
        })

    cleaned_devices = []
    for i, item in enumerate(devices, start=1):
        if not isinstance(item, dict) or not str(item.get("ip_address") or "").strip():
            raise ValueError(f"Device #{i} is missing ip_address.")
        monitored = item.get("monitored", True)
        if isinstance(monitored, str):
            monitored = monitored.strip().lower() in ("1", "true", "yes", "y")
        cleaned_devices.append({
            "ip_address": str(item["ip_address"]).strip(),
            "asset_tag": blank_to_none(item.get("asset_tag")) or "",
            "name": blank_to_none(item.get("name")) or "",
            "building": blank_to_none(item.get("building")) or "",
            "location": blank_to_none(item.get("location")) or "",
            "comment": blank_to_none(item.get("comment")) or "",
            "monitored": bool(monitored),
            "vendor": blank_to_none(item.get("vendor")) or "",
            "model": blank_to_none(item.get("model")) or "",
            "credential_profile": blank_to_none(item.get("credential_profile")) or "",
        })

    return {
        "version": raw.get("version", INVENTORY_VERSION),
        "buildings": cleaned_buildings,
        "devices": cleaned_devices,
    }


def import_inventory(db: Session, inventory: dict[str, Any], dry_run: bool = False) -> dict[str, int]:
    """Add missing buildings and devices. Existing names/IPs are skipped, not overwritten."""
    stats = {
        "buildings_added": 0,
        "buildings_skipped": 0,
        "devices_added": 0,
        "devices_skipped": 0,
        "profiles_unresolved": 0,
    }

    for item in inventory.get("buildings", []):
        existing = db.query(Building).filter(Building.name == item["name"]).first()
        if existing:
            stats["buildings_skipped"] += 1
            continue
        db.add(Building(name=item["name"], description=item.get("description") or None))
        stats["buildings_added"] += 1

    db.flush()

    for item in inventory.get("devices", []):
        ip = item["ip_address"]
        existing = db.query(Device).filter(Device.ip_address == ip).first()
        if existing:
            stats["devices_skipped"] += 1
            continue

        asset_tag = blank_to_none(item.get("asset_tag"))
        if asset_tag and db.query(Device).filter(Device.asset_tag == asset_tag).first():
            stats["devices_skipped"] += 1
            continue

        building_name = item.get("building") or None
        if building_name and not db.query(Building).filter(Building.name == building_name).first():
            db.add(Building(name=building_name))
            stats["buildings_added"] += 1
            db.flush()

        profile_name = item.get("credential_profile") or ""
        profile_id = None
        if profile_name:
            profile = (
                db.query(CredentialProfile)
                .filter(CredentialProfile.name == profile_name)
                .first()
            )
            if profile:
                profile_id = profile.id
            else:
                stats["profiles_unresolved"] += 1

        db.add(Device(
            ip_address=ip,
            asset_tag=asset_tag,
            name=item.get("name") or None,
            building=building_name,
            location=item.get("location") or None,
            comment=item.get("comment") or None,
            monitored=item.get("monitored", True),
            vendor=item.get("vendor") or None,
            model=item.get("model") or None,
            credential_profile_id=profile_id,
        ))
        stats["devices_added"] += 1

    if dry_run:
        db.rollback()
    else:
        db.commit()

    return stats
