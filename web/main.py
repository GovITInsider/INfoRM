from fastapi import FastAPI, Request, Form, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader
from collections import defaultdict

from inform.core.database import SessionLocal
from inform.core.models import Device, Building, AlarmEvent
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
from inform.version import __version__
from inform.core.timeutils import to_local

from inform.core.database import ensure_db_permissions
from starlette.responses import RedirectResponse
from sqlalchemy import text


# Ensure database permissions on startup
ensure_db_permissions()

app = FastAPI(title="INfoRM", version=__version__)

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

# enable url_for in templates
templates.globals["url_for"] = app.url_path_for

# ========================
# Helper
# ========================
def device_to_dict(device):
    return {
        "id": device.id,
        "asset_tag": device.asset_tag or "-",
        "ip_address": device.ip_address,
        "name": device.name or "-",
        "building": device.building or "-",
        "location": device.location or "-",
        "comment": device.comment or "-",
        "status": device.status,
        "failure_count": device.failure_count,
        "response_time": device.response_time,
        "last_checked": device.last_checked.strftime('%Y-%m-%d %H:%M:%S') if device.last_checked else 'Never',
        "monitored": device.monitored,
    }


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
# Device Management
# ========================

@app.get("/manage/devices", response_class=HTMLResponse)
async def manage_devices(request: Request, edit: int = None, user=Depends(manager)):
    db = SessionLocal()
    try:
        devices = db.query(Device).order_by(Device.ip_address).all()
        buildings = db.query(Building).order_by(Building.name).all()
        edit_device = db.query(Device).filter(Device.id == edit).first() if edit else None

        return templates.get_template("manage/devices.html").render(
            request=request,
            devices=devices,
            buildings=buildings,
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
                #print(f"Set device.comment to: '{device.comment}'")  # for debug
        else:  # Adding new
            existing = db.query(Device).filter(Device.ip_address == ip_address.strip()).first()
            if existing:
                devices = db.query(Device).order_by(Device.ip_address).all()
                buildings = db.query(Building).order_by(Building.name).all()
                return templates.get_template("manage/devices.html").render(
                    request=request,
                    devices=devices,
                    buildings=buildings,
                    error=f"Device with IP {ip_address} already exists."
                )

            device = Device(
                ip_address=ip_address.strip(),
                asset_tag=asset_tag.strip() if asset_tag else None,
                name=name.strip() if name else None,
                building=building,
                location=location.strip() if location else None,
                comment=comment.strip() if comment else None,
                monitored=monitored
            )
            db.add(device)

        db.commit()
        return RedirectResponse(url="/manage/devices?success=Device added/edited successfully", status_code=302)
    except Exception as e:
        db.rollback()
        devices = db.query(Device).order_by(Device.ip_address).all()
        buildings = db.query(Building).order_by(Building.name).all()
        html = templates.get_template("manage/devices.html").render(
            request=request,
            devices=devices,
            buildings=buildings,
            error=str(e)
        )
        return HTMLResponse(content=html, status_code=200)
    finally:
        db.close()

@app.get("/manage/devices/{device_id}/delete")
async def delete_device(device_id: int, user=Depends(manager)):
    db = SessionLocal()
    try:
        device = db.query(Device).filter(Device.id == device_id).first()
        if device:
            db.delete(device)
            db.commit()
        return RedirectResponse(url="/manage/devices?success=Device deleted successfully", status_code=302)
    finally:
        db.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
