"""IANA enterprise-number → vendor display string. Not a SKU catalog."""

from __future__ import annotations

import re

ENTERPRISE_VENDORS: dict[int, str] = {
    9: "Cisco",
    25461: "Palo Alto Networks",
    2636: "Juniper",
    14823: "Aruba (HPE)",
    11: "HP / HPE",
    674: "Dell",
    12356: "Fortinet",
    318: "APC",
    3375: "F5",
    6876: "VMware",
}

_ENTERPRISE_OID_RE = re.compile(
    r"^\.?1\.3\.6\.1\.4\.1\.(\d+)(?:\.|$)",
)


def vendor_from_sys_object_id(sys_object_id: str | None) -> str | None:
    """Map sysObjectID to a vendor string.

    Unknown enterprise → ``Unknown ({n})``. Empty or unparseable → None.
    """
    if not sys_object_id:
        return None
    text = str(sys_object_id).strip().strip('"')
    if not text:
        return None
    match = _ENTERPRISE_OID_RE.match(text)
    if not match:
        return None
    enterprise = int(match.group(1))
    return ENTERPRISE_VENDORS.get(enterprise, f"Unknown ({enterprise})")
