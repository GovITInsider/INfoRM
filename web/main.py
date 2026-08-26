import logging
from contextlib import asynccontextmanager
from datetime import datetime
from types import SimpleNamespace
from urllib.parse import urlencode
from fastapi import FastAPI, Request, Form, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader
from collections import defaultdict

from inform.core.database import SessionLocal, ensure_db_permissions, ensure_schema
from inform.snmp.scan import (
    cancel_current_scan,
    fail_interrupted_sessions,
    begin_scan,
    start_scan_task,
    request_cancel,
    ScanAlreadyRunning,
    UnsavedReviewError,
    PublicSpaceError,
    DiscoveryDisabledError,
    clamp_scan_options,
)
from inform.core.models import (
    Device,
    Building,
    AlarmEvent,
    CredentialProfile,
    DiscoveryJob,
    ScanResult,
    ScanSession,
)
from inform.core.config import settings
from inform.core.auth import (
    manager,
    verify_password,
    load_user,
    NotAuthenticatedException,
    issue_session,
    clear_session,
    username_from_token,
)
from inform.core.inventory import build_inventory, dump_inventory_yaml
from inform.core.secrets import encrypt_secret
from inform.version import __version__
from inform.core.timeutils import to_local
from inform.snmp.client import SnmpEngine, SnmpErrorKind, identify
from inform.snmp.targets import TargetParseError, parse_scan_target

from starlette.responses import RedirectResponse
from sqlalchemy import exists, func, text
from sqlalchemy.exc import IntegrityError

logger = logging.getLogger("inform.web")


# Ensure database permissions on startup
ensure_db_permissions()


@asynccontextmanager
async def lifespan(app: FastAPI):
    ensure_schema()
    fail_interrupted_sessions("interrupted by process restart")
    yield
    await cancel_current_scan()


app = FastAPI(title="INfoRM", version=__version__, lifespan=lifespan)

app.mount("/static", StaticFiles(directory="web/static"), name="static")


@app.exception_handler(NotAuthenticatedException)
async def not_authenticated_handler(request: Request, exc: NotAuthenticatedException):
    return RedirectResponse(url="/manage/login", status_code=302)


@app.middleware("http")
async def sliding_admin_session(request: Request, call_next):
    """Refresh the admin cookie on each manage request so activity keeps the session alive."""
    response = await call_next(request)
    path = request.url.path
    if path.startswith("/manage") and path not in ("/manage/login", "/manage/logout"):
        username = username_from_token(request.cookies.get("access_token"))
        if username:
            issue_session(response, username)
    return response

# ========================
# Jinja2 Setup
# ========================
templates = Environment(
    loader=FileSystemLoader("web/templates"),
    auto_reload=True
)
templates.globals["app_version"] = __version__
templates.globals["discovery_enabled"] = settings.discovery.enabled

# enable url_for in templates
templates.globals["url_for"] = app.url_path_for

# ========================
# Helper
# ========================
def device_to_dict(device):
    vendor = device.vendor or ""
    model = device.model or ""
    return {
        "id": device.id,
        "asset_tag": device.asset_tag or "-",
        "ip_address": device.ip_address,
        "name": device.name or "-",
        "building": device.building or "-",
        "location": device.location or "-",
        "vendor": vendor,
        "model": model,
        "comment": device.comment or "-",
        "status": device.status,
        "failure_count": device.failure_count,
        "response_time": device.response_time,
        "last_checked": device.last_checked.strftime('%Y-%m-%d %H:%M:%S') if device.last_checked else 'Never',
        "monitored": device.monitored,
    }


_VALID_VERSIONS = ("v1", "v2c", "v3")
_VALID_LEVELS = {
    "authpriv": "authPriv",
    "authnopriv": "authNoPriv",
    "noauthnopriv": "noAuthNoPriv",
}
_VALID_AUTH = ("md5", "sha", "sha256")
_VALID_PRIV = ("des", "aes", "aes128")


def _public_profile(profile, device_count=0):
    """Template-safe profile dict. Never includes community, auth_key, or priv_key."""
    return {
        "id": profile.id,
        "name": profile.name,
        "description": profile.description or "",
        "snmp_version": profile.snmp_version or "v3",
        "security_level": profile.security_level or "",
        "username": profile.username or "",
        "auth_protocol": profile.auth_protocol or "",
        "priv_protocol": profile.priv_protocol or "",
        "community_set": bool(profile.community),
        "auth_key_set": bool(profile.auth_key),
        "priv_key_set": bool(profile.priv_key),
        "device_count": device_count,
    }


def _device_form_profiles(db):
    """id/name/version only — no secret columns in the device-form template context."""
    rows = (
        db.query(
            CredentialProfile.id,
            CredentialProfile.name,
            CredentialProfile.snmp_version,
        )
        .order_by(CredentialProfile.name)
        .all()
    )
    return [
        {"id": row.id, "name": row.name, "snmp_version": row.snmp_version or "v3"}
        for row in rows
    ]


def _detached_snmp_profile(profile):
    """Copy identify()/auth_from_profile columns so the DB session can close first."""
    return SimpleNamespace(
        id=profile.id,
        name=profile.name,
        snmp_version=profile.snmp_version,
        security_level=profile.security_level or "",
        community=profile.community,
        username=profile.username or "",
        auth_protocol=profile.auth_protocol or "",
        auth_key=profile.auth_key or "",
        priv_protocol=profile.priv_protocol or "",
        priv_key=profile.priv_key or "",
    )


def _form_from_public(pub):
    return {
        "name": pub.get("name", ""),
        "description": pub.get("description", ""),
        "snmp_version": pub.get("snmp_version") or "v3",
        "security_level": pub.get("security_level") or "authPriv",
        "username": pub.get("username", ""),
        "auth_protocol": pub.get("auth_protocol") or "sha",
        "priv_protocol": pub.get("priv_protocol") or "aes",
    }


def _posted_profile_form(
    name, description, snmp_version, security_level, username, auth_protocol, priv_protocol
):
    return {
        "name": (name or "").strip(),
        "description": (description or "").strip(),
        "snmp_version": (snmp_version or "v3").strip(),
        "security_level": (security_level or "authPriv").strip(),
        "username": (username or "").strip(),
        "auth_protocol": (auth_protocol or "sha").strip().lower(),
        "priv_protocol": (priv_protocol or "aes").strip().lower(),
    }


def _list_public_profiles(db):
    profiles = db.query(CredentialProfile).order_by(CredentialProfile.name).all()
    counts = dict(
        db.query(Device.credential_profile_id, func.count(Device.id))
        .group_by(Device.credential_profile_id)
        .all()
    )
    return [_public_profile(p, counts.get(p.id, 0)) for p in profiles]


def _render_profiles_page(request, db, *, error=None, test_result=None, edit_id=None, form=None):
    pubs = _list_public_profiles(db)
    edit_profile = None
    if edit_id:
        edit_profile = next((p for p in pubs if p["id"] == edit_id), None)
    if form is None:
        form = _form_from_public(edit_profile) if edit_profile else {}
    return templates.get_template("manage/profiles.html").render(
        request=request,
        profiles=pubs,
        edit_profile=edit_profile,
        form=form,
        error=error,
        test_result=test_result,
    )


def _keep_or_encrypt(new_value, existing):
    if new_value:
        return encrypt_secret(new_value) or ""
    if existing:
        return existing
    return ""


def _build_profile_fields(form, *, community, auth_key, priv_key, existing=None):
    """Validate posted profile fields. Returns (fields, error). Never echoes secrets."""
    name = form["name"]
    if not name:
        return None, "Name is required."
    if len(name) > 50:
        return None, "Name must be 50 characters or fewer."
    description = form["description"] or None
    if description and len(description) > 200:
        return None, "Description must be 200 characters or fewer."

    version = form["snmp_version"].lower()
    if version not in _VALID_VERSIONS:
        return None, "SNMP version must be v1, v2c, or v3."

    community = (community or "").strip()
    username = form["username"]
    if len(username) > 50:
        return None, "Username must be 50 characters or fewer."
    auth_key = (auth_key or "").strip()
    priv_key = (priv_key or "").strip()
    auth_protocol = form["auth_protocol"]
    priv_protocol = form["priv_protocol"]

    fields = {
        "name": name,
        "description": description,
        "snmp_version": version,
        "security_level": "",
        "community": None,
        "username": "",
        "auth_protocol": "",
        "auth_key": "",
        "priv_protocol": "",
        "priv_key": "",
    }

    if version in ("v1", "v2c"):
        stored = existing.community if existing else None
        if not community and not stored:
            return None, "Community is required for v1/v2c profiles."
        fields["community"] = encrypt_secret(community) if community else stored
        return fields, None

    level = _VALID_LEVELS.get(form["security_level"].replace(" ", "").lower())
    if level is None:
        return None, "Security level must be authPriv, authNoPriv, or noAuthNoPriv."
    if not username:
        return None, "Username is required for SNMPv3."
    fields["username"] = username
    fields["security_level"] = level
    fields["community"] = None

    if level in ("authNoPriv", "authPriv"):
        if auth_protocol not in _VALID_AUTH:
            return None, "Auth protocol must be sha, sha256, or md5."
        stored_auth = existing.auth_key if existing and (existing.snmp_version or "").lower() == "v3" else ""
        if not auth_key and not stored_auth:
            return None, "Authentication key is required for this security level."
        fields["auth_protocol"] = auth_protocol
        fields["auth_key"] = _keep_or_encrypt(auth_key, stored_auth)

    if level == "authPriv":
        if priv_protocol not in _VALID_PRIV:
            return None, "Privacy protocol must be aes or des."
        stored_priv = existing.priv_key if existing and (existing.snmp_version or "").lower() == "v3" else ""
        if not priv_key and not stored_priv:
            return None, "Privacy key is required for authPriv."
        fields["priv_protocol"] = priv_protocol
        fields["priv_key"] = _keep_or_encrypt(priv_key, stored_priv)

    return fields, None


def _apply_profile_fields(profile, fields):
    profile.name = fields["name"]
    profile.description = fields["description"]
    profile.snmp_version = fields["snmp_version"]
    profile.security_level = fields["security_level"]
    profile.community = fields["community"]
    profile.username = fields["username"]
    profile.auth_protocol = fields["auth_protocol"]
    profile.auth_key = fields["auth_key"]
    profile.priv_protocol = fields["priv_protocol"]
    profile.priv_key = fields["priv_key"]


def _parse_test_ip(raw):
    text = (raw or "").strip()
    if not text:
        raise ValueError("IP address is required")
    if "/" in text:
        raise ValueError("Test requires a single IPv4 address")
    parsed = parse_scan_target(text)
    return str(parsed.hosts[0])


def _optional_int(raw):
    text = "" if raw is None else str(raw).strip()
    if not text:
        return None
    try:
        return int(text)
    except (TypeError, ValueError):
        return None


def _checkbox(raw) -> bool:
    text = ("" if raw is None else str(raw)).strip().lower()
    return text in ("1", "true", "on", "yes")


def _parse_id_list(values) -> list:
    out = []
    for raw in values or ():
        n = _optional_int(raw)
        if n and n > 0 and n not in out:
            out.append(n)
    return out


def _iso_z(dt):
    if dt is None:
        return None
    return dt.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _form_text(form, key, default=""):
    if form is None:
        return default
    val = form.get(key)
    if val is None:
        return default
    return str(val)


def _discover_form_defaults():
    ping_t, ping_c, snmp_t, snmp_c = clamp_scan_options()
    return {
        "target": "",
        "default_building": "",
        "profile_ids": [],
        "confirm_public": False,
        "discard_previous": False,
        "ping_timeout_seconds": ping_t,
        "ping_concurrency": ping_c,
        "snmp_timeout_seconds": snmp_t,
        "snmp_concurrency": snmp_c,
    }


def _discover_disabled_redirect():
    if not settings.discovery.enabled:
        return RedirectResponse(url="/manage", status_code=302)
    return None


def _has_unsaved_review(db, session_id):
    if not session_id:
        return False
    return (
        db.query(ScanResult.id)
        .filter(
            ScanResult.session_id == session_id,
            ScanResult.already_managed.is_not(True),
            ~exists().where(Device.ip_address == ScanResult.ip_address),
        )
        .first()
        is not None
    )


def _scan_status_payload(session):
    if session is None:
        return {
            "id": None,
            "status": "none",
            "target": None,
            "total_hosts": 0,
            "pinged_count": 0,
            "live_count": 0,
            "snmp_done_count": 0,
            "cancel_requested": False,
            "error_message": None,
            "started_at": None,
            "elapsed_seconds": 0,
        }
    now = datetime.utcnow()
    start = session.started_at
    end = session.finished_at or now
    elapsed = 0
    if start is not None:
        elapsed = max(0, int((end - start).total_seconds()))
    return {
        "id": session.id,
        "status": session.status,
        "target": session.target,
        "total_hosts": session.total_hosts or 0,
        "pinged_count": session.pinged_count or 0,
        "live_count": session.live_count or 0,
        "snmp_done_count": session.snmp_done_count or 0,
        "cancel_requested": bool(session.cancel_requested),
        "error_message": session.error_message,
        "started_at": _iso_z(session.started_at),
        "elapsed_seconds": elapsed,
    }


def _progress_pct(payload):
    total = payload.get("total_hosts") or 0
    if total <= 0:
        return 0
    pinged = payload.get("pinged_count") or 0
    live = payload.get("live_count") or 0
    snmp_done = payload.get("snmp_done_count") or 0
    ping_frac = min(pinged, total) / total
    if pinged >= total and live > 0:
        frac = 0.5 * ping_frac + 0.5 * min(snmp_done, live) / live
    else:
        frac = ping_frac
    return max(0, min(100, int(round(frac * 100))))


def _ordered_profiles(profiles, selected_ids):
    by_id = {p["id"]: p for p in profiles}
    ordered = []
    seen = set()
    for pid in selected_ids or ():
        row = by_id.get(pid)
        if row is not None and pid not in seen:
            ordered.append(row)
            seen.add(pid)
    for row in profiles:
        if row["id"] not in seen:
            ordered.append(row)
    return ordered


def _review_rows(db, session, form=None):
    if session is None:
        return []
    results = (
        db.query(ScanResult)
        .filter(ScanResult.session_id == session.id)
        .order_by(ScanResult.ip_address)
        .all()
    )
    managed_ips = {ip for (ip,) in db.query(Device.ip_address).all()}
    default_building = session.default_building or ""
    selected_ids = set()
    if form is not None:
        selected_ids = {str(n) for n in _parse_id_list(form.getlist("selected"))}
    rows = []
    for r in results:
        in_inv = bool(r.already_managed) or r.ip_address in managed_ips
        addable = (not in_inv) and bool(r.ping_ok)
        rid = str(r.id)
        if form is not None:
            name = _form_text(form, f"name_{r.id}", r.name or "")
            location = _form_text(form, f"location_{r.id}", r.location or "")
            building = _form_text(form, f"building_{r.id}", default_building)
            comment = _form_text(form, f"comment_{r.id}", "")
            asset_tag = _form_text(form, f"asset_tag_{r.id}", "")
            monitored = form.get(f"monitored_{r.id}") is not None
            selected = rid in selected_ids or str(r.id) in selected_ids
        else:
            name = r.name or ""
            location = r.location or ""
            building = default_building
            comment = ""
            asset_tag = ""
            monitored = True
            selected = False
        rows.append(
            {
                "id": r.id,
                "ip_address": r.ip_address,
                "already_managed": in_inv,
                "addable": addable,
                "ping_ok": bool(r.ping_ok),
                "ping_rtt_ms": r.ping_rtt_ms,
                "snmp_status": r.snmp_status or "skipped",
                "name": name,
                "location": location,
                "vendor": r.vendor or "",
                "model": r.model or "",
                "building": building,
                "comment": comment,
                "asset_tag": asset_tag,
                "monitored": monitored,
                "selected": selected,
            }
        )
    return rows


def _load_scan_session(db, scan_id=None):
    if scan_id:
        row = db.query(ScanSession).filter(ScanSession.id == scan_id).first()
        if row is not None:
            return row
    return db.query(ScanSession).order_by(ScanSession.id.desc()).first()


def _render_discover_page(
    request,
    db,
    *,
    error=None,
    form=None,
    scan_id=None,
    posted_form=None,
    require_public=False,
):
    buildings = db.query(Building).order_by(Building.name).all()
    profiles = _device_form_profiles(db)
    session = _load_scan_session(db, scan_id)
    if form is None:
        form = _discover_form_defaults()
        if session is not None and session.default_building:
            form["default_building"] = session.default_building
    form_profiles = _ordered_profiles(profiles, form.get("profile_ids") or [])
    needs_discard = False
    if session is not None and session.status in ("completed", "cancelled", "failed"):
        needs_discard = _has_unsaved_review(db, session.id)
    payload = _scan_status_payload(session)
    scan_busy = session is not None and session.status in ("running", "cancelling")
    rows = _review_rows(db, session, posted_form)
    return templates.get_template("manage/discover.html").render(
        request=request,
        buildings=buildings,
        profiles=form_profiles,
        form=form,
        error=error,
        session=session,
        results=rows,
        needs_discard=needs_discard,
        require_public=require_public,
        scan_busy=scan_busy,
        progress=payload,
        progress_pct=_progress_pct(payload),
    )


def _devices_redirect(*, edit=None, success=None, error=None):
    params = {}
    if edit is not None:
        params["edit"] = str(edit)
    if success:
        params["success"] = success
    if error:
        params["error"] = error
    url = "/manage/devices"
    if params:
        url = f"{url}?{urlencode(params)}"
    return RedirectResponse(url=url, status_code=302)


def _snmp_refresh_error_label(err):
    if err == SnmpErrorKind.TIMEOUT:
        return "timeout"
    if err == SnmpErrorKind.AUTH:
        return "auth"
    return "no SNMP"


# ========================
# Public Routes
# ========================

@app.get("/", response_class=HTMLResponse)
async def landing_page(request: Request):
    db = SessionLocal()
    try:
        devices = db.query(Device).all()
        total = len(devices)
        up = sum(1 for d in devices if d.status == "up")
        pre_alarm = sum(1 for d in devices if d.status == "pre-alarm")
        down = sum(1 for d in devices if d.status == "down")

        return templates.get_template("landing.html").render(
            request=request,
            stats={"total": total, "up": up, "pre_alarm": pre_alarm, "down": down}
        )
    finally:
        db.close()


# ========================
# NOC View (Public)
# ========================
@app.get("/noc", response_class=HTMLResponse)
async def noc_page(request: Request):
    db = SessionLocal()
    try:
        devices = db.query(Device).filter(Device.monitored == True).all()

        # Overall stats
        total = len(devices)
        up = sum(1 for d in devices if d.status == "up")
        pre_alarm = sum(1 for d in devices if d.status == "pre-alarm")
        down = sum(1 for d in devices if d.status == "down")

        # Overall response time stats
        up_devices = [d for d in devices if d.status == "up" and d.response_time is not None]
        if up_devices:
            rtt_values = [d.response_time for d in up_devices]
            min_rtt = min(rtt_values)
            avg_rtt = round(sum(rtt_values) / len(rtt_values), 1)
            max_rtt = max(rtt_values)
        else:
            min_rtt = avg_rtt = max_rtt = None

        # Building grouping + per-building average RTT (only UP devices)
        building_groups = defaultdict(list)
        for d in devices:
            building_name = d.building or "Unknown"
            building_groups[building_name].append(d)

        tiles = []
        for building_name, devs in building_groups.items():
            total_mon = len(devs)
            down_count = sum(1 for d in devs if d.status == "down")

            # Calculate average RTT only for UP devices in this building
            building_up = [d for d in devs if d.status == "up" and d.response_time is not None]
            if building_up:
                avg = sum(d.response_time for d in building_up) / len(building_up)
                building_avg_rtt = round(avg, 1)
            else:
                building_avg_rtt = None

            if down_count == total_mon and total_mon > 0:
                color = "danger"
                status_text = "ALL DOWN"
            elif down_count > 0:
                color = "warning"
                status_text = f"{down_count}/{total_mon} DOWN"
            else:
                color = "success"
                status_text = "ALL UP"

            tiles.append({
                "name": building_name,
                "color": color,
                "total": total_mon,
                "down": down_count,
                "status_text": status_text,
                "avg_rtt": building_avg_rtt,
            })

        # Sort: Red → Yellow → Green, then alphabetically
        severity_order = {"danger": 0, "warning": 1, "success": 2}
        tiles.sort(key=lambda x: (severity_order.get(x["color"], 3), x["name"].lower()))

        problem_tiles = [t for t in tiles if t["color"] in ("danger", "warning")]
        healthy_tiles = [t for t in tiles if t["color"] == "success"]

        return templates.get_template("noc.html").render(
            request=request,
            stats={
                "total": total,
                "up": up,
                "pre_alarm": pre_alarm,
                "down": down,
                "min_rtt": min_rtt,
                "avg_rtt": avg_rtt,
                "max_rtt": max_rtt,
            },
            problem_tiles=problem_tiles,
            healthy_tiles=healthy_tiles,
            noc_auto_refresh_seconds=settings.web.noc_auto_refresh_seconds,
        )
    finally:
        db.close()

@app.get("/devices", response_class=HTMLResponse)
async def devices_page(request: Request):
    db = SessionLocal()
    try:
        devices = db.query(Device).all()
    
        # Convert last_checked to local time
        for d in devices:
            d.last_checked = to_local(d.last_checked)

        # default sort by status
        severity = {
                "down": 0,
                "pre-alarm": 1,
                "unknown": 2,
                "up": 3
        }
        devices.sort(key=lambda d: (severity.get(d.status, 99), d.name or d.ip_address or ""))
        # end sorting

        device_list = [device_to_dict(d) for d in devices]

        return templates.get_template("devices.html").render(
            request=request,
            devices=device_list
        )
    finally:
        db.close()


@app.get("/history", response_class=HTMLResponse)
async def alarm_history(request: Request):
    db = SessionLocal()
    try:
        events = (
            db.query(AlarmEvent)
            .order_by(AlarmEvent.timestamp.desc())
            .limit(100)
            .all()
        )

        #convert timestamp to local time
        for event in events:
            event.timestamp = to_local(event.timestamp)


        return templates.get_template("history.html").render(
            request=request,
            events=events
        )
    finally:
        db.close()

@app.get("/help", response_class=HTMLResponse)
async def help_page(request: Request):
    return templates.get_template("help.html").render(request=request)


@app.get("/about", response_class=HTMLResponse)
async def about_page(request: Request):
    return templates.get_template("about.html").render(request=request)

# ========================
# Health Check - helpful we secuting behind a load balancer...
# ========================

@app.get("/health")
async def health_check():
    try:
        # Quick database connectivity check
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": "healthy",
                "service": "INfoRM"
            }
        )
    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "unhealthy",
                "error": str(e)
            }
        )

# ========================
# Authentication Routes
# ========================

@app.get("/manage/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.get_template("login.html").render(request=request, error=None)

@app.post("/manage/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    user = load_user(username)

    if not user or not verify_password(password, user.hashed_password):
        html = templates.get_template("login.html").render(
            request=request,
            error="Invalid username or password"
        )
        return HTMLResponse(content=html)

    # Login successful
    response = RedirectResponse(url="/manage", status_code=302)
    issue_session(response, user.username)
    return response


@app.get("/manage/logout")
async def logout():
    response = RedirectResponse(url="/manage/login", status_code=302)
    clear_session(response)
    return response


# ========================
# Protected Route 
# ========================

@app.get("/manage", response_class=HTMLResponse)
async def manage_dashboard(request: Request):
    # Manually check auth
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse(url="/manage/login", status_code=302)

    try:
        user = await manager.get_current_user(token)
    except Exception:
        return RedirectResponse(url="/manage/login", status_code=302)

    return templates.get_template("manage/dashboard.html").render(
        request=request,
        user=user,
        session_hours=max(1, int(settings.security.token_expires_minutes / 60)),
    )

# ========================
# Inventory export
# ========================

@app.get("/manage/export")
async def export_inventory(user=Depends(manager)):
    db = SessionLocal()
    try:
        body = dump_inventory_yaml(build_inventory(db))
        return Response(
            content=body,
            media_type="application/yaml",
            headers={"Content-Disposition": 'attachment; filename="inform-inventory.yaml"'},
        )
    finally:
        db.close()


# ========================
# Building Management
# ========================

@app.get("/manage/buildings", response_class=HTMLResponse)
async def manage_buildings(request: Request, edit: int = None, user=Depends(manager)):
    db = SessionLocal()
    try:
        buildings = db.query(Building).order_by(Building.name).all()
        edit_building = None
        if edit:
            edit_building = db.query(Building).filter(Building.id == edit).first()

        return templates.get_template("manage/buildings.html").render(
            request=request,
            buildings=buildings,
            edit_building=edit_building
        )
    finally:
        db.close()


@app.post("/manage/buildings")
async def add_or_update_building(
    request: Request,
    name: str = Form(...),
    building_id: int = Form(None),
    user=Depends(manager)
):
    db = SessionLocal()
    try:
        if building_id:  # Editing existing building
            building = db.query(Building).filter(Building.id == building_id).first()
            if building:
                building.name = name
        else:  # Adding new building
            existing = db.query(Building).filter(Building.name == name).first()
            if existing:
                buildings = db.query(Building).order_by(Building.name).all()
                return templates.get_template("manage/buildings.html").render(
                    request=request,
                    buildings=buildings,
                    error=f"Building '{name}' already exists."
                )
            building = Building(name=name)
            db.add(building)

        db.commit()
        return RedirectResponse(url="/manage/buildings?success=Building added/edited successfully", status_code=302)
    finally:
        db.close()


@app.get("/manage/buildings/{building_id}/delete")
async def delete_building(building_id: int, user=Depends(manager)):
    db = SessionLocal()
    try:
        building = db.query(Building).filter(Building.id == building_id).first()
        if building:
            db.delete(building)
            db.commit()
            return RedirectResponse(url="/manage/buildings?success=Building deleted successfully", status_code=302)
    finally:
        db.close()

# ========================
# Credential Profile Management
# ========================

@app.get("/manage/profiles", response_class=HTMLResponse)
async def manage_profiles(request: Request, edit: int = None, user=Depends(manager)):
    db = SessionLocal()
    try:
        html = _render_profiles_page(request, db, edit_id=edit)
        return HTMLResponse(content=html)
    finally:
        db.close()


@app.post("/manage/profiles")
async def add_or_update_profile(
    request: Request,
    name: str = Form(""),
    description: str = Form(""),
    snmp_version: str = Form("v3"),
    security_level: str = Form("authPriv"),
    community: str = Form(""),
    username: str = Form(""),
    auth_protocol: str = Form("sha"),
    auth_key: str = Form(""),
    priv_protocol: str = Form("aes"),
    priv_key: str = Form(""),
    profile_id: str = Form(""),
    user=Depends(manager),
):
    form = _posted_profile_form(
        name, description, snmp_version, security_level, username, auth_protocol, priv_protocol
    )
    profile_id = _optional_int(profile_id)
    db = SessionLocal()
    try:
        existing = None
        if profile_id:
            existing = db.query(CredentialProfile).filter(CredentialProfile.id == profile_id).first()
            if not existing:
                html = _render_profiles_page(request, db, error="Profile not found.", form=form)
                return HTMLResponse(content=html)

        dup = db.query(CredentialProfile).filter(CredentialProfile.name == form["name"])
        if profile_id:
            dup = dup.filter(CredentialProfile.id != profile_id)
        if dup.first():
            html = _render_profiles_page(
                request, db, error=f"Profile '{form['name']}' already exists.",
                edit_id=profile_id, form=form,
            )
            return HTMLResponse(content=html)

        fields, error = _build_profile_fields(
            form,
            community=community,
            auth_key=auth_key,
            priv_key=priv_key,
            existing=existing,
        )
        if error:
            html = _render_profiles_page(
                request, db, error=error, edit_id=profile_id, form=form,
            )
            return HTMLResponse(content=html)

        if existing:
            _apply_profile_fields(existing, fields)
        else:
            profile = CredentialProfile()
            _apply_profile_fields(profile, fields)
            db.add(profile)

        db.commit()
        return RedirectResponse(
            url="/manage/profiles?success=Profile added/edited successfully",
            status_code=302,
        )
    except Exception:
        db.rollback()
        logger.error("Failed to save credential profile")
        html = _render_profiles_page(
            request, db, error="Failed to save profile.", edit_id=profile_id, form=form,
        )
        return HTMLResponse(content=html, status_code=200)
    finally:
        db.close()


@app.get("/manage/profiles/{profile_id}/delete")
async def delete_profile(profile_id: int, user=Depends(manager)):
    db = SessionLocal()
    try:
        profile = db.query(CredentialProfile).filter(CredentialProfile.id == profile_id).first()
        if profile:
            # Application-level cleanup; PRAGMA foreign_keys stays off.
            db.query(Device).filter(Device.credential_profile_id == profile_id).update(
                {Device.credential_profile_id: None},
                synchronize_session=False,
            )
            db.query(DiscoveryJob).filter(DiscoveryJob.credential_profile_id == profile_id).delete(
                synchronize_session=False,
            )
            db.query(ScanResult).filter(ScanResult.credential_profile_id == profile_id).update(
                {ScanResult.credential_profile_id: None},
                synchronize_session=False,
            )
            db.delete(profile)
            db.commit()
        return RedirectResponse(
            url="/manage/profiles?success=Profile deleted successfully",
            status_code=302,
        )
    finally:
        db.close()


@app.post("/manage/profiles/{profile_id}/test")
async def test_profile(
    request: Request,
    profile_id: int,
    ip: str = Form(""),
    user=Depends(manager),
):
    db = SessionLocal()
    try:
        profile = db.query(CredentialProfile).filter(CredentialProfile.id == profile_id).first()
        if not profile:
            html = _render_profiles_page(request, db, error="Profile not found.")
            return HTMLResponse(content=html)

        try:
            test_ip = _parse_test_ip(ip)
        except (ValueError, TargetParseError) as exc:
            html = _render_profiles_page(request, db, error=str(exc))
            return HTMLResponse(content=html)

        snmp_profile = _detached_snmp_profile(profile)
        profile_name = profile.name
    finally:
        db.rollback()
        db.close()

    timeout = float(settings.discovery.default_snmp_timeout_seconds)
    engine = SnmpEngine()
    try:
        identity, err, _ = await identify(
            engine, test_ip, [snmp_profile], timeout, retries=1,
        )
    except Exception as exc:
        logger.error(
            "SNMP profile test failed for %s profile %s: %s",
            test_ip,
            profile_name,
            type(exc).__name__,
        )
        identity, err = None, SnmpErrorKind.OTHER
    finally:
        engine.close_dispatcher()

    if identity is not None:
        result = {
            "ok": True,
            "ip": test_ip,
            "profile_name": profile_name,
            "sys_name": identity.sys_name,
            "sys_location": identity.sys_location,
            "vendor": identity.vendor,
            "model": identity.model,
            "sys_object_id": identity.sys_object_id,
        }
        logger.info(
            "SNMP profile test user=%s profile=%s ip=%s result=ok",
            getattr(user, "username", None),
            profile_name,
            test_ip,
        )
    else:
        if err == SnmpErrorKind.TIMEOUT:
            err_label = "timeout"
        elif err == SnmpErrorKind.AUTH:
            err_label = "auth fail"
        else:
            err_label = "failed"
        result = {
            "ok": False,
            "ip": test_ip,
            "profile_name": profile_name,
            "error": err_label,
        }
        logger.info(
            "SNMP profile test user=%s profile=%s ip=%s result=%s",
            getattr(user, "username", None),
            profile_name,
            test_ip,
            err_label,
        )

    db = SessionLocal()
    try:
        html = _render_profiles_page(request, db, test_result=result)
        return HTMLResponse(content=html)
    finally:
        db.rollback()
        db.close()

# ========================
# Device Management
# ========================

@app.get("/manage/devices", response_class=HTMLResponse)
async def manage_devices(request: Request, edit: int = None, user=Depends(manager)):
    db = SessionLocal()
    try:
        devices = db.query(Device).order_by(Device.ip_address).all()
        buildings = db.query(Building).order_by(Building.name).all()
        profiles = _device_form_profiles(db)
        edit_device = db.query(Device).filter(Device.id == edit).first() if edit else None

        return templates.get_template("manage/devices.html").render(
            request=request,
            devices=devices,
            buildings=buildings,
            profiles=profiles,
            edit_device=edit_device
        )
    finally:
        db.close()


@app.post("/manage/devices")
async def save_device(
    request: Request,
    ip_address: str = Form(...),
    asset_tag: str = Form(""),
    name: str = Form(""),
    building: str = Form(...),
    location: str = Form(""),
    comment: str = Form(""),
    monitored: bool = Form(False),
    credential_profile_id: str = Form(""),
    device_id: int = Form(None),
    user=Depends(manager)
):
    db = SessionLocal()
    try:
        # ========== TEMPORARY DEBUG ==========
        #print("=== SAVE DEVICE DEBUG ===")
        #print(f"device_id     = {device_id}")
        #print(f"ip_address    = {ip_address}")
        #print(f"comment received from form = '{comment}'")
        # =======================================================

        profile_fk = None
        credential_profile_id = _optional_int(credential_profile_id)
        if credential_profile_id:
            cred = db.query(CredentialProfile).filter(
                CredentialProfile.id == credential_profile_id
            ).first()
            if not cred:
                devices = db.query(Device).order_by(Device.ip_address).all()
                buildings = db.query(Building).order_by(Building.name).all()
                profiles = _device_form_profiles(db)
                return templates.get_template("manage/devices.html").render(
                    request=request,
                    devices=devices,
                    buildings=buildings,
                    profiles=profiles,
                    error="Credential profile not found.",
                )
            profile_fk = cred.id

        if device_id:  # Editing
            device = db.query(Device).filter(Device.id == device_id).first()
            if device:
                #print(f"Found device: {device.ip_address}")          # for debug
                device.ip_address = ip_address.strip()
                device.asset_tag = asset_tag.strip() if asset_tag else None
                device.name = name.strip() if name else None
                device.building = building
                device.location = location.strip() if location else None
                device.comment = comment.strip() if comment else None
                device.monitored = monitored
                device.credential_profile_id = profile_fk
                #print(f"Set device.comment to: '{device.comment}'")  # for debug
        else:  # Adding new
            existing = db.query(Device).filter(Device.ip_address == ip_address.strip()).first()
            if existing:
                devices = db.query(Device).order_by(Device.ip_address).all()
                buildings = db.query(Building).order_by(Building.name).all()
                profiles = _device_form_profiles(db)
                return templates.get_template("manage/devices.html").render(
                    request=request,
                    devices=devices,
                    buildings=buildings,
                    profiles=profiles,
                    error=f"Device with IP {ip_address} already exists."
                )

            device = Device(
                ip_address=ip_address.strip(),
                asset_tag=asset_tag.strip() if asset_tag else None,
                name=name.strip() if name else None,
                building=building,
                location=location.strip() if location else None,
                comment=comment.strip() if comment else None,
                monitored=monitored,
                credential_profile_id=profile_fk,
            )
            db.add(device)

        db.commit()
        return RedirectResponse(url="/manage/devices?success=Device added/edited successfully", status_code=302)
    except Exception as e:
        db.rollback()
        devices = db.query(Device).order_by(Device.ip_address).all()
        buildings = db.query(Building).order_by(Building.name).all()
        profiles = _device_form_profiles(db)
        html = templates.get_template("manage/devices.html").render(
            request=request,
            devices=devices,
            buildings=buildings,
            profiles=profiles,
            error=str(e)
        )
        return HTMLResponse(content=html, status_code=200)
    finally:
        db.close()


@app.post("/manage/devices/{device_id}/refresh-snmp")
async def refresh_device_snmp(
    device_id: int,
    refresh_profile_id: str = Form(""),
    try_all: bool = Form(False),
    update_name: bool = Form(False),
    user=Depends(manager),
):
    db = SessionLocal()
    ip = None
    profiles_to_try = []
    load_error = None
    try:
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            load_error = "Device not found."
        else:
            ip = device.ip_address
            linked_id = device.credential_profile_id
            if linked_id:
                # Linked profile only — never walk others unless the operator unsets it.
                row = db.query(CredentialProfile).filter(
                    CredentialProfile.id == linked_id
                ).first()
                if row:
                    profiles_to_try = [_detached_snmp_profile(row)]
                else:
                    load_error = "SNMP refresh failed: no SNMP"
            else:
                rows = (
                    db.query(CredentialProfile)
                    .order_by(CredentialProfile.name)
                    .all()
                )
                if try_all:
                    profiles_to_try = [_detached_snmp_profile(p) for p in rows]
                else:
                    chosen_id = _optional_int(refresh_profile_id)
                    if chosen_id is None and rows:
                        chosen_id = rows[0].id
                    row = next((p for p in rows if p.id == chosen_id), None)
                    if row:
                        profiles_to_try = [_detached_snmp_profile(row)]
                if not profiles_to_try:
                    load_error = "SNMP refresh failed: no SNMP"
    finally:
        db.rollback()
        db.close()

    if load_error or not profiles_to_try or not ip:
        return _devices_redirect(
            edit=device_id if ip else None,
            error=load_error or "SNMP refresh failed: no SNMP",
        )

    timeout = float(settings.discovery.default_snmp_timeout_seconds)
    engine = SnmpEngine()
    try:
        identity, err, _ = await identify(
            engine, ip, profiles_to_try, timeout, retries=1,
        )
    except Exception as exc:
        logger.error(
            "SNMP refresh failed for %s device %s: %s",
            ip,
            device_id,
            type(exc).__name__,
        )
        identity, err = None, SnmpErrorKind.OTHER
    finally:
        engine.close_dispatcher()

    if identity is None:
        err_label = _snmp_refresh_error_label(err)
        logger.info(
            "SNMP refresh user=%s device=%s ip=%s result=%s",
            getattr(user, "username", None),
            device_id,
            ip,
            err_label,
        )
        return _devices_redirect(
            edit=device_id,
            error=f"SNMP refresh failed: {err_label}",
        )

    db = SessionLocal()
    try:
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            return _devices_redirect(error="Device not found.")
        device.location = identity.sys_location
        device.vendor = identity.vendor
        device.model = identity.model
        device.sys_object_id = identity.sys_object_id
        device.credential_profile_id = identity.profile_id
        if update_name:
            device.name = identity.sys_name
        db.commit()
        logger.info(
            "SNMP refresh user=%s device=%s ip=%s result=ok",
            getattr(user, "username", None),
            device_id,
            ip,
        )
        return _devices_redirect(edit=device_id, success="SNMP identity refreshed")
    except Exception:
        db.rollback()
        return _devices_redirect(
            edit=device_id,
            error="SNMP refresh failed: no SNMP",
        )
    finally:
        db.close()


@app.get("/manage/devices/{device_id}/delete")
async def delete_device(device_id: int, user=Depends(manager)):
    db = SessionLocal()
    try:
        device = db.query(Device).filter(Device.id == device_id).first()
        if device:
            # Application-level SET NULL; PRAGMA foreign_keys stays off (K21).
            db.query(ScanResult).filter(ScanResult.managed_device_id == device_id).update(
                {ScanResult.managed_device_id: None},
                synchronize_session=False,
            )
            db.delete(device)
            db.commit()
        return RedirectResponse(url="/manage/devices?success=Device deleted successfully", status_code=302)
    finally:
        db.close()


# ========================
# Discover (on-demand scan + bulk add)
# ========================

@app.get("/manage/discover", response_class=HTMLResponse)
async def manage_discover(request: Request, scan: int = None, user=Depends(manager)):
    disabled = _discover_disabled_redirect()
    if disabled:
        return disabled
    db = SessionLocal()
    try:
        html = _render_discover_page(request, db, scan_id=scan)
        return HTMLResponse(content=html)
    finally:
        db.close()


@app.post("/manage/discover/start")
async def start_discover(
    request: Request,
    target: str = Form(""),
    default_building: str = Form(""),
    confirm_public: str = Form(""),
    discard_previous: str = Form(""),
    ping_timeout_seconds: str = Form(""),
    ping_concurrency: str = Form(""),
    snmp_timeout_seconds: str = Form(""),
    snmp_concurrency: str = Form(""),
    user=Depends(manager),
):
    disabled = _discover_disabled_redirect()
    if disabled:
        return disabled

    posted = await request.form()
    profile_ids = _parse_id_list(posted.getlist("profile_ids"))
    form = {
        "target": (target or "").strip(),
        "default_building": (default_building or "").strip(),
        "profile_ids": profile_ids,
        "confirm_public": _checkbox(confirm_public),
        "discard_previous": _checkbox(discard_previous),
        "ping_timeout_seconds": _optional_int(ping_timeout_seconds),
        "ping_concurrency": _optional_int(ping_concurrency),
        "snmp_timeout_seconds": _optional_int(snmp_timeout_seconds),
        "snmp_concurrency": _optional_int(snmp_concurrency),
    }
    defaults = _discover_form_defaults()
    for key in (
        "ping_timeout_seconds",
        "ping_concurrency",
        "snmp_timeout_seconds",
        "snmp_concurrency",
    ):
        if form[key] is None:
            form[key] = defaults[key]

    db = SessionLocal()
    try:
        if db.query(Building.id).first() is None:
            html = _render_discover_page(
                request, db, error="Add a building before adding devices.", form=form,
            )
            return HTMLResponse(content=html)

        building_names = {name for (name,) in db.query(Building.name).all()}
        stored_building = form["default_building"] or None
        if stored_building and stored_building not in building_names:
            stored_building = None

        if profile_ids:
            existing_ids = {
                pid
                for (pid,) in db.query(CredentialProfile.id)
                .filter(CredentialProfile.id.in_(profile_ids))
                .all()
            }
            profile_ids = [pid for pid in profile_ids if pid in existing_ids]
            form["profile_ids"] = profile_ids

        # Release the IMMEDIATE read lock before begin_scan's own transaction.
        db.rollback()
        try:
            session_id = begin_scan(
                form["target"],
                profile_ids=profile_ids,
                default_building=stored_building,
                ping_timeout_seconds=form["ping_timeout_seconds"],
                ping_concurrency=form["ping_concurrency"],
                snmp_timeout_seconds=form["snmp_timeout_seconds"],
                snmp_concurrency=form["snmp_concurrency"],
                confirm_public=form["confirm_public"],
                discard_previous=form["discard_previous"],
                started_by=getattr(user, "username", None),
            )
        except DiscoveryDisabledError:
            return RedirectResponse(url="/manage", status_code=302)
        except TargetParseError as exc:
            html = _render_discover_page(request, db, error=str(exc), form=form)
            return HTMLResponse(content=html)
        except PublicSpaceError as exc:
            html = _render_discover_page(
                request, db, error=str(exc), form=form, require_public=True,
            )
            return HTMLResponse(content=html)
        except UnsavedReviewError:
            html = _render_discover_page(
                request,
                db,
                error="Check “Discard the current review grid and start a new scan” to continue.",
                form=form,
            )
            return HTMLResponse(content=html)
        except ScanAlreadyRunning as exc:
            html = _render_discover_page(
                request,
                db,
                error="A scan is already running. Cancel it before starting another.",
                form=form,
                scan_id=exc.session_id,
            )
            return HTMLResponse(content=html)

        start_scan_task(session_id)
        return RedirectResponse(url=f"/manage/discover?scan={session_id}", status_code=302)
    finally:
        db.close()


@app.get("/manage/discover/status")
async def discover_status(scan: int = None, user=Depends(manager)):
    disabled = _discover_disabled_redirect()
    if disabled:
        return disabled
    db = SessionLocal()
    try:
        session = _load_scan_session(db, scan)
        return JSONResponse(_scan_status_payload(session))
    finally:
        db.close()


@app.post("/manage/discover/cancel")
async def cancel_discover(scan_id: str = Form(""), user=Depends(manager)):
    sid = _optional_int(scan_id)
    request_cancel(sid)
    if sid:
        return RedirectResponse(url=f"/manage/discover?scan={sid}", status_code=302)
    return RedirectResponse(url="/manage/discover", status_code=302)


@app.post("/manage/discover/save")
async def save_discover(
    request: Request,
    scan_id: str = Form(""),
    user=Depends(manager),
):
    disabled = _discover_disabled_redirect()
    if disabled:
        return disabled

    posted = await request.form()
    sid = _optional_int(scan_id)
    selected_ids = _parse_id_list(posted.getlist("selected"))

    db = SessionLocal()
    try:
        session = db.query(ScanSession).filter(ScanSession.id == sid).first() if sid else None
        if session is None:
            html = _render_discover_page(
                request, db, error="Scan not found.", posted_form=posted,
            )
            return HTMLResponse(content=html)

        if session.status in ("running", "cancelling"):
            html = _render_discover_page(
                request,
                db,
                error="Wait for the scan to finish before saving.",
                scan_id=sid,
                posted_form=posted,
            )
            return HTMLResponse(content=html)

        if db.query(Building.id).first() is None:
            html = _render_discover_page(
                request,
                db,
                error="Add a building before adding devices.",
                scan_id=sid,
                posted_form=posted,
            )
            return HTMLResponse(content=html)

        rows = []
        if selected_ids:
            found = {
                r.id: r
                for r in db.query(ScanResult)
                .filter(
                    ScanResult.session_id == sid,
                    ScanResult.id.in_(selected_ids),
                )
                .all()
            }
            rows = [found[i] for i in selected_ids if i in found]

        existing_ips = {ip for (ip,) in db.query(Device.ip_address).all()}
        to_add = []
        for row in rows:
            if row.already_managed:
                continue
            if row.ip_address in existing_ips:
                continue
            if not row.ping_ok:
                continue
            to_add.append(row)

        if not to_add:
            html = _render_discover_page(
                request,
                db,
                error="No new devices selected.",
                scan_id=sid,
                posted_form=posted,
            )
            return HTMLResponse(content=html)

        missing_building = []
        pending = []
        tags_seen = {}
        for row in to_add:
            building = _form_text(posted, f"building_{row.id}").strip()
            if not building:
                missing_building.append(row.ip_address)
            name = _form_text(posted, f"name_{row.id}").strip() or None
            location = _form_text(posted, f"location_{row.id}").strip() or None
            comment = _form_text(posted, f"comment_{row.id}").strip() or None
            asset_tag = _form_text(posted, f"asset_tag_{row.id}").strip() or None
            monitored = posted.get(f"monitored_{row.id}") is not None
            pending.append(
                {
                    "row": row,
                    "building": building,
                    "name": name,
                    "location": location,
                    "comment": comment,
                    "asset_tag": asset_tag,
                    "monitored": monitored,
                }
            )
            if asset_tag:
                tags_seen.setdefault(asset_tag, []).append(row.ip_address)

        if missing_building:
            html = _render_discover_page(
                request,
                db,
                error="Building is required for: " + ", ".join(missing_building),
                scan_id=sid,
                posted_form=posted,
            )
            return HTMLResponse(content=html)

        batch_dupes = [tag for tag, ips in tags_seen.items() if len(ips) > 1]
        if batch_dupes:
            html = _render_discover_page(
                request,
                db,
                error="Duplicate asset tags in selection: " + ", ".join(sorted(batch_dupes)),
                scan_id=sid,
                posted_form=posted,
            )
            return HTMLResponse(content=html)

        existing_tags = set()
        wanted_tags = [tag for tag in tags_seen if tag]
        if wanted_tags:
            existing_tags = {
                tag
                for (tag,) in db.query(Device.asset_tag)
                .filter(Device.asset_tag.in_(wanted_tags))
                .all()
            }
        if existing_tags:
            html = _render_discover_page(
                request,
                db,
                error="Asset tag already exists: " + ", ".join(sorted(existing_tags)),
                scan_id=sid,
                posted_form=posted,
            )
            return HTMLResponse(content=html)

        added = 0
        for item in pending:
            row = item["row"]
            profile_fk = row.credential_profile_id if row.snmp_status == "ok" else None
            db.add(
                Device(
                    ip_address=row.ip_address,
                    asset_tag=item["asset_tag"],
                    name=item["name"],
                    building=item["building"],
                    location=item["location"],
                    comment=item["comment"],
                    monitored=item["monitored"],
                    vendor=row.vendor,
                    model=row.model,
                    sys_object_id=row.sys_object_id,
                    credential_profile_id=profile_fk,
                    status="unknown",
                    failure_count=0,
                )
            )
            added += 1

        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            html = _render_discover_page(
                request,
                db,
                error="A device IP or asset tag is already in inventory.",
                scan_id=sid,
                posted_form=posted,
            )
            return HTMLResponse(content=html)

        logger.info(
            "discover save user=%s added=%s scan=%s",
            getattr(user, "username", None),
            added,
            sid,
        )
        return RedirectResponse(
            url=f"/manage/devices?success=Added {added} device(s)",
            status_code=302,
        )
    finally:
        db.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
