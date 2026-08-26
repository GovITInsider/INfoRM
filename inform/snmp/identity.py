"""Vendor + chassis model + sysDescr fallback. Pure functions, no SNMP I/O."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Sequence

CHASSIS_CLASS = 3
STACK_CLASS = 11
MODEL_MAX_LEN = 100
NAME_MAX_LEN = 100

SYSDESCR_PATTERNS: dict[str, re.Pattern[str]] = {
    "Cisco": re.compile(
        r"\b(C9[0-9]{3}[A-Z0-9-]*|WS-C[A-Z0-9-]+|ISR[0-9]{4}|ASR[0-9]{4}|N[0-9]{1,4}[A-Z0-9-]*)\b"
    ),
    "Palo Alto Networks": re.compile(r"\bPA-[0-9]+[A-Z0-9-]*\b"),
    "Fortinet": re.compile(r"\bFortiGate-[A-Z0-9-]+\b"),
    "Aruba (HPE)": re.compile(r"\b(JL[0-9]{3}[A-Z]?|Aruba [0-9]{4}[A-Z0-9-]*)\b"),
    "Juniper": re.compile(r"\b(EX[0-9]{3,4}[A-Z0-9-]*|SRX[0-9]{3,4}[A-Z0-9-]*)\b"),
    "F5": re.compile(r"\bBIG-IP[A-Z0-9 -]*\b"),
}


@dataclass(frozen=True)
class EntityRow:
    index: int
    physical_class: int | None
    model_name: str | None
    contained_in: int | None


def truncate_name(value: str | None, limit: int = NAME_MAX_LEN) -> str | None:
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    return text[:limit]


def clean_model_name(value: str | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip().strip('"').strip()
    if not text:
        return None
    return text[:MODEL_MAX_LEN]


def contained_in_is_root(value: int | None) -> bool:
    return value == 0


def pick_chassis_model(rows: Sequence[EntityRow]) -> str | None:
    """Rank ENTITY-MIB rows: rooted chassis, then any chassis, then stack."""
    chassis: list[EntityRow] = []
    stacks: list[EntityRow] = []
    for row in rows:
        if not clean_model_name(row.model_name):
            continue
        if row.physical_class == CHASSIS_CLASS:
            chassis.append(row)
        elif row.physical_class == STACK_CLASS:
            stacks.append(row)

    rooted = [r for r in chassis if contained_in_is_root(r.contained_in)]
    if rooted:
        return clean_model_name(min(rooted, key=lambda r: r.index).model_name)
    if chassis:
        return clean_model_name(min(chassis, key=lambda r: r.index).model_name)
    if stacks:
        return clean_model_name(min(stacks, key=lambda r: r.index).model_name)
    return None


def model_from_sysdescr(vendor: str | None, sys_descr: str | None) -> str | None:
    if not vendor or not sys_descr:
        return None
    pattern = SYSDESCR_PATTERNS.get(vendor)
    if pattern is None:
        return None
    match = pattern.search(sys_descr)
    if not match:
        return None
    return clean_model_name(match.group(0))
