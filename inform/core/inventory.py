"""Export/import buildings and devices as a YAML inventory file."""

from __future__ import annotations

from typing import Any

import yaml
from sqlalchemy.orm import Session

from inform.core.models import Building, Device

INVENTORY_VERSION = 1


def build_inventory(db: Session) -> dict[str, Any]:
    buildings = db.query(Building).order_by(Building.name).all()
    devices = db.query(Device).order_by(Device.ip_address).all()
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
            "asset_tag": str(item.get("asset_tag") or "").strip(),
            "name": str(item.get("name") or "").strip(),
            "building": str(item.get("building") or "").strip(),
            "location": str(item.get("location") or "").strip(),
            "comment": str(item.get("comment") or "").strip(),
            "monitored": bool(monitored),
        })

    return {"version": raw.get("version", INVENTORY_VERSION), "buildings": cleaned_buildings, "devices": cleaned_devices}


def import_inventory(db: Session, inventory: dict[str, Any], dry_run: bool = False) -> dict[str, int]:
    """Add missing buildings and devices. Existing names/IPs are skipped, not overwritten."""
    stats = {
        "buildings_added": 0,
        "buildings_skipped": 0,
        "devices_added": 0,
        "devices_skipped": 0,
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

        asset_tag = item.get("asset_tag") or None
        if asset_tag and db.query(Device).filter(Device.asset_tag == asset_tag).first():
            stats["devices_skipped"] += 1
            continue

        building_name = item.get("building") or None
        if building_name and not db.query(Building).filter(Building.name == building_name).first():
            db.add(Building(name=building_name))
            stats["buildings_added"] += 1
            db.flush()

        db.add(Device(
            ip_address=ip,
            asset_tag=asset_tag,
            name=item.get("name") or None,
            building=building_name,
            location=item.get("location") or None,
            comment=item.get("comment") or None,
            monitored=item.get("monitored", True),
        ))
        stats["devices_added"] += 1

    if dry_run:
        db.rollback()
    else:
        db.commit()

    return stats
