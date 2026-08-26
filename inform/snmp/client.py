"""pysnmp 7.1 asyncio SNMP client. Numeric OIDs only; secrets decrypted at use."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Sequence

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    USM_AUTH_HMAC96_MD5,
    USM_AUTH_HMAC96_SHA,
    USM_AUTH_HMAC192_SHA256,
    USM_PRIV_CBC56_DES,
    USM_PRIV_CFB128_AES,
    bulk_cmd,
    get_cmd,
    is_end_of_mib,
    next_cmd,
    usmNoAuthProtocol,
    usmNoPrivProtocol,
)

from inform.core.models import CredentialProfile
from inform.core.secrets import decrypt_secret
from inform.snmp.identity import (
    CHASSIS_CLASS,
    EntityRow,
    clean_model_name,
    model_from_sysdescr,
    pick_chassis_model,
    truncate_name,
)
from inform.snmp.vendors import vendor_from_sys_object_id

logger = logging.getLogger("inform.snmp")

SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
ENT_CONTAINED_IN = "1.3.6.1.2.1.47.1.1.1.1.4"
ENT_CLASS = "1.3.6.1.2.1.47.1.1.1.1.5"
ENT_MODEL_NAME = "1.3.6.1.2.1.47.1.1.1.1.13"

ENT_CLASS_PREFIX = (1, 3, 6, 1, 2, 1, 47, 1, 1, 1, 1, 5)
MAX_BULK_PDUS = 3
MAX_CLASS_INDEXES = 60
BULK_MAX_REPETITIONS = 20
SNMP_PORT = 161

AUTH_PROTOCOLS = {
    "md5": USM_AUTH_HMAC96_MD5,
    "sha": USM_AUTH_HMAC96_SHA,
    "sha256": USM_AUTH_HMAC192_SHA256,
}
PRIV_PROTOCOLS = {
    "des": USM_PRIV_CBC56_DES,
    "aes": USM_PRIV_CFB128_AES,
    "aes128": USM_PRIV_CFB128_AES,
}

_AUTH_ERROR_TOKENS = (
    "unknownusername",
    "wrongdigest",
    "wrongdigests",
    "decryptionerror",
    "authenticationfailure",
    "authenticationerror",
    "unknowncommunityname",
    "unknownsecurityname",
    "unsupportedsecuritylevel",
    "authorizationerror",
    "noaccess",
)
_TIMEOUT_TOKENS = (
    "requesttimedout",
    "nosnmpresponsereceivedbeforetimeout",
)


class SnmpErrorKind(str, Enum):
    TIMEOUT = "timeout"
    AUTH = "auth"
    OTHER = "other"


@dataclass
class SnmpIdentity:
    sys_name: str | None
    sys_location: str | None
    sys_object_id: str | None
    vendor: str | None
    model: str | None
    profile_id: int | None


def auth_from_profile(profile: CredentialProfile):
    """Build pysnmp auth from a profile. Always decrypts secrets; never logs them."""
    profile_id = getattr(profile, "id", None)
    profile_name = getattr(profile, "name", None)

    def _dec(val: str | None) -> str | None:
        return decrypt_secret(val, profile_id=profile_id, profile_name=profile_name)

    version = (profile.snmp_version or "v3").lower()
    if version in ("v1", "v2c"):
        community = _dec(profile.community) or ""
        mp_model = 0 if version == "v1" else 1
        return CommunityData(community, mpModel=mp_model)

    user = profile.username or ""
    level = (profile.security_level or "authPriv").replace(" ", "").lower()
    if level == "noauthnopriv":
        return UsmUserData(user, authProtocol=usmNoAuthProtocol, privProtocol=usmNoPrivProtocol)

    auth_proto = AUTH_PROTOCOLS.get((profile.auth_protocol or "sha").lower(), USM_AUTH_HMAC96_SHA)
    auth_key = _dec(profile.auth_key) or ""
    if level == "authnopriv":
        return UsmUserData(user, authKey=auth_key, authProtocol=auth_proto)

    priv_proto = PRIV_PROTOCOLS.get((profile.priv_protocol or "aes").lower(), USM_PRIV_CFB128_AES)
    priv_key = _dec(profile.priv_key) or ""
    return UsmUserData(
        user,
        authKey=auth_key,
        privKey=priv_key,
        authProtocol=auth_proto,
        privProtocol=priv_proto,
    )


def _profile_label(profile: CredentialProfile) -> str:
    return getattr(profile, "name", None) or str(getattr(profile, "id", "?"))


def _oid_tuple(obj) -> tuple[int, ...]:
    if hasattr(obj, "__iter__") and not isinstance(obj, (str, bytes)):
        try:
            return tuple(int(x) for x in obj)
        except (TypeError, ValueError):
            pass
    text = str(obj).split("=", 1)[0].strip().strip('"').lstrip(".")
    parts = []
    for piece in text.split("."):
        if piece.isdigit():
            parts.append(int(piece))
        else:
            break
    return tuple(parts)


def _is_absent(val) -> bool:
    name = type(val).__name__
    if name in ("NoSuchObject", "NoSuchInstance", "EndOfMibView", "Null"):
        return True
    text = str(val).strip().strip('"')
    return text.lower() in (
        "",
        "nosuchobject",
        "nosuchinstance",
        "endofmibview",
        "none",
        "null",
    )


def _text_value(val) -> str | None:
    if val is None or _is_absent(val):
        return None
    text = str(val).strip().strip('"').strip()
    return text or None


def _oid_str(val) -> str | None:
    if val is None or _is_absent(val):
        return None
    oid = _oid_tuple(val)
    if oid:
        return ".".join(str(n) for n in oid)
    text = _text_value(val)
    if not text:
        return None
    return text.lstrip(".")


def _int_value(val) -> int | None:
    if val is None or _is_absent(val):
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        pass
    text = _text_value(val)
    if text is None:
        return None
    if text in ("0.0",):
        return 0
    try:
        return int(text)
    except ValueError:
        return None


def _classify_error(error_indication, error_status) -> SnmpErrorKind:
    if error_status:
        try:
            code = int(error_status)
            if code in (6, 16):  # noAccess, authorizationError
                return SnmpErrorKind.AUTH
            if code == 2:  # noSuchName is a missing OID, not auth
                return SnmpErrorKind.OTHER
        except (TypeError, ValueError):
            pass
    tokens: list[str] = []
    if error_indication is not None:
        tokens.append(type(error_indication).__name__.lower())
        tokens.append(str(error_indication).lower().replace(" ", ""))
    if error_status:
        try:
            pretty = error_status.prettyPrint() if hasattr(error_status, "prettyPrint") else str(error_status)
        except Exception:
            pretty = str(error_status)
        tokens.append(str(pretty).lower().replace(" ", ""))
    blob = " ".join(tokens)
    if any(tok in blob for tok in _AUTH_ERROR_TOKENS):
        return SnmpErrorKind.AUTH
    if any(tok in blob for tok in _TIMEOUT_TOKENS):
        return SnmpErrorKind.TIMEOUT
    if error_indication is not None:
        return SnmpErrorKind.TIMEOUT
    return SnmpErrorKind.OTHER


def _obj(*oids: str) -> tuple[ObjectType, ...]:
    return tuple(ObjectType(ObjectIdentity(oid)) for oid in oids)


async def _transport(ip: str, timeout: float, retries: int) -> UdpTransportTarget:
    return await UdpTransportTarget.create((ip, SNMP_PORT), timeout=timeout, retries=retries)


async def _snmp_get(engine, auth, transport, *oids: str):
    return await get_cmd(
        engine,
        auth,
        transport,
        ContextData(),
        *_obj(*oids),
        lookupMib=False,
    )


def _varbind_map(var_binds) -> dict[tuple[int, ...], object]:
    result: dict[tuple[int, ...], object] = {}
    for bind in var_binds or ():
        result[_oid_tuple(bind[0])] = bind[1]
    return result


def _lookup(vmap: dict[tuple[int, ...], object], dotted: str):
    key = _oid_tuple(dotted)
    if key in vmap:
        return vmap[key]
    for oid, val in vmap.items():
        if oid == key:
            return val
    return None


async def _fetch_chassis_model(engine, auth, transport, version: str) -> str | None:
    error_indication, error_status, _, var_binds = await _snmp_get(
        engine,
        auth,
        transport,
        f"{ENT_CLASS}.1",
        f"{ENT_MODEL_NAME}.1",
    )
    if not error_indication and not error_status:
        vmap = _varbind_map(var_binds)
        class_1 = _int_value(_lookup(vmap, f"{ENT_CLASS}.1"))
        model_1 = clean_model_name(_text_value(_lookup(vmap, f"{ENT_MODEL_NAME}.1")))
        if class_1 == CHASSIS_CLASS and model_1:
            return model_1

    class_by_index: dict[int, int] = {}
    if (version or "v3").lower() == "v1":
        await _walk_class_v1(engine, auth, transport, class_by_index)
    else:
        await _walk_class_bulk(engine, auth, transport, class_by_index)

    chassis_idx = [i for i, cls in class_by_index.items() if cls == CHASSIS_CLASS]
    if not chassis_idx:
        chassis_idx = [i for i, cls in class_by_index.items() if cls == 11]
    if not chassis_idx:
        return None

    get_oids: list[str] = []
    for idx in chassis_idx:
        get_oids.append(f"{ENT_MODEL_NAME}.{idx}")
        get_oids.append(f"{ENT_CONTAINED_IN}.{idx}")
    error_indication, error_status, _, var_binds = await _snmp_get(
        engine, auth, transport, *get_oids
    )
    if error_indication or error_status:
        return None
    vmap = _varbind_map(var_binds)
    rows: list[EntityRow] = []
    for idx in chassis_idx:
        rows.append(
            EntityRow(
                index=idx,
                physical_class=class_by_index.get(idx),
                model_name=_text_value(_lookup(vmap, f"{ENT_MODEL_NAME}.{idx}")),
                contained_in=_int_value(_lookup(vmap, f"{ENT_CONTAINED_IN}.{idx}")),
            )
        )
    return pick_chassis_model(rows)


async def _walk_class_bulk(engine, auth, transport, class_by_index: dict[int, int]) -> None:
    cursor = ENT_CLASS
    for _ in range(MAX_BULK_PDUS):
        if len(class_by_index) >= MAX_CLASS_INDEXES:
            break
        error_indication, error_status, _, var_binds = await bulk_cmd(
            engine,
            auth,
            transport,
            ContextData(),
            0,
            BULK_MAX_REPETITIONS,
            ObjectType(ObjectIdentity(cursor)),
            lookupMib=False,
        )
        if error_indication or error_status:
            break
        if not var_binds or is_end_of_mib(var_binds):
            break
        left_column = False
        last_oid = cursor
        for bind in var_binds:
            oid = _oid_tuple(bind[0])
            if len(oid) <= len(ENT_CLASS_PREFIX) or oid[: len(ENT_CLASS_PREFIX)] != ENT_CLASS_PREFIX:
                left_column = True
                break
            idx = oid[-1]
            cls = _int_value(bind[1])
            if cls is not None:
                class_by_index[idx] = cls
            last_oid = ".".join(str(n) for n in oid)
            if len(class_by_index) >= MAX_CLASS_INDEXES:
                return
        if left_column:
            break
        if last_oid == cursor:
            break
        cursor = last_oid


async def _walk_class_v1(engine, auth, transport, class_by_index: dict[int, int]) -> None:
    cursor = ENT_CLASS
    for _ in range(MAX_CLASS_INDEXES):
        error_indication, error_status, _, var_binds = await next_cmd(
            engine,
            auth,
            transport,
            ContextData(),
            ObjectType(ObjectIdentity(cursor)),
            lookupMib=False,
        )
        if error_indication or error_status or not var_binds or is_end_of_mib(var_binds):
            break
        bind = var_binds[0]
        oid = _oid_tuple(bind[0])
        if len(oid) <= len(ENT_CLASS_PREFIX) or oid[: len(ENT_CLASS_PREFIX)] != ENT_CLASS_PREFIX:
            break
        idx = oid[-1]
        cls = _int_value(bind[1])
        if cls is not None:
            class_by_index[idx] = cls
        next_oid = ".".join(str(n) for n in oid)
        if next_oid == cursor:
            break
        cursor = next_oid


async def identify(
    engine: SnmpEngine,
    ip: str,
    profiles: Sequence[CredentialProfile],
    timeout: float,
    retries: int = 0,
) -> tuple[SnmpIdentity | None, SnmpErrorKind | None, int | None]:
    """Try profiles in order. First successful sysObjectID/sysName GET wins."""
    transport = await _transport(ip, timeout, retries)
    kinds: list[SnmpErrorKind] = []

    for profile in profiles:
        label = _profile_label(profile)
        try:
            auth = auth_from_profile(profile)
            error_indication, error_status, _, var_binds = await _snmp_get(
                engine,
                auth,
                transport,
                SYS_OBJECT_ID,
                SYS_NAME,
                SYS_LOCATION,
                SYS_DESCR,
            )
            if error_indication or error_status:
                kind = _classify_error(error_indication, error_status)
                kinds.append(kind)
                logger.debug("SNMP %s profile %s: %s", ip, label, kind.value)
                continue

            vmap = _varbind_map(var_binds)
            sys_object_id = _oid_str(_lookup(vmap, SYS_OBJECT_ID))
            sys_name = truncate_name(_text_value(_lookup(vmap, SYS_NAME)))
            sys_location = truncate_name(_text_value(_lookup(vmap, SYS_LOCATION)))
            sys_descr = _text_value(_lookup(vmap, SYS_DESCR))
            if not sys_object_id and not sys_name:
                kinds.append(SnmpErrorKind.OTHER)
                logger.debug("SNMP %s profile %s: empty identity", ip, label)
                continue

            vendor = vendor_from_sys_object_id(sys_object_id)
            model = None
            try:
                model = await _fetch_chassis_model(
                    engine, auth, transport, profile.snmp_version or "v3"
                )
            except Exception:
                logger.debug("ENTITY-MIB walk failed for %s profile %s", ip, label)
            if not model:
                model = model_from_sysdescr(vendor, sys_descr)

            identity = SnmpIdentity(
                sys_name=sys_name,
                sys_location=sys_location,
                sys_object_id=sys_object_id[:256] if sys_object_id else None,
                vendor=vendor,
                model=model,
                profile_id=getattr(profile, "id", None),
            )
            logger.debug("SNMP %s profile %s: ok", ip, label)
            return identity, None, identity.profile_id
        except Exception as exc:
            logger.error(
                "SNMP identify failed for %s profile %s: %s",
                ip,
                label,
                type(exc).__name__,
            )
            kinds.append(SnmpErrorKind.OTHER)

    if any(k == SnmpErrorKind.AUTH for k in kinds):
        return None, SnmpErrorKind.AUTH, None
    if any(k == SnmpErrorKind.TIMEOUT for k in kinds):
        return None, SnmpErrorKind.TIMEOUT, None
    return None, SnmpErrorKind.OTHER, None


def get_device_info(ip: str, profile: CredentialProfile, timeout: float = 2.0):
    # CLI only — web must await identify().
    async def _run():
        engine = SnmpEngine()
        try:
            identity, err, _ = await identify(engine, ip, [profile], timeout, retries=1)
            if identity is None:
                if err == SnmpErrorKind.TIMEOUT:
                    return {"error": "SNMP request timed out"}
                if err == SnmpErrorKind.AUTH:
                    return {"error": "SNMP authentication failed"}
                return {"error": "SNMP request failed"}
            return {
                "sysName": identity.sys_name or "",
                "sysLocation": identity.sys_location or "",
                "sysObjectID": identity.sys_object_id or "",
                "vendor": identity.vendor or "",
                "model": identity.model or "",
            }
        finally:
            engine.close_dispatcher()

    try:
        return asyncio.run(_run())
    except Exception:
        return {"error": "SNMP request failed"}
