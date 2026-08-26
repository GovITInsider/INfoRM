import warnings
from sqlalchemy.exc import SAWarning

# Suppress the "declarative base already contains" warning
warnings.filterwarnings("ignore", category=SAWarning)

import asyncio
import typer
from rich import print as rprint
from rich.table import Table
from rich.console import Console
from sqlalchemy.orm import Session

from inform.core.database import SessionLocal
from inform.core.models import Building, CredentialProfile, Device
from inform.core.config import settings
from inform.core.secrets import encrypt_secret
from inform.snmp.client import get_device_info
from inform.snmp.scan import clamp_scan_options, probe_hosts
from inform.snmp.targets import TargetParseError, parse_scan_target



app = typer.Typer(
    name="inform",
    help="INfoRM - Network Reachability Monitor (Python version)",
    add_completion=False,
)
console = Console()

from inform.cli.inventory_cmds import register_inventory
register_inventory(app)


# ============================================================
# Basic Commands
# ============================================================

@app.command()
def version():
    """Show the current version of INfoRM"""
    from inform.version import __version__
    rprint("[bold cyan]INfoRM[/bold cyan] - Python Rewrite")
    rprint(f"Version: [green]{__version__}[/green]")


@app.command()
def init_db():
    """Initialize the SQLite database and create tables"""
    try:
        from inform.core.database import init_db as _init_db
        _init_db()
        rprint("[green]✓[/green] Database initialized successfully")
    except Exception as e:
        rprint(f"[red]Error initializing database:[/red] {e}")


@app.command()
def status():
    """Show basic status of INfoRM"""
    rprint("[bold]INfoRM Status[/bold]")
    rprint(f"Poll interval: [cyan]{settings.general.poll_interval_seconds}[/cyan] seconds")
    rprint(f"Discovery enabled: [cyan]{settings.discovery.enabled}[/cyan]")
    rprint(f"Log level: [cyan]{settings.general.log_level}[/cyan]")


# ============================================================
# Credential Profile Commands
# ============================================================

def _prompt_secret(label: str, current: str | None) -> str:
    if current:
        return current
    return typer.prompt(label, hide_input=True)


def _normalize_security_level(raw: str) -> str | None:
    key = (raw or "authPriv").replace(" ", "").lower()
    mapping = {
        "authpriv": "authPriv",
        "authnopriv": "authNoPriv",
        "noauthnopriv": "noAuthNoPriv",
    }
    return mapping.get(key)


@app.command()
def add_profile(
    name: str = typer.Option(..., prompt=True, help="Profile name (e.g. cisco, f5)"),
    description: str = typer.Option("", prompt=True, help="Optional description"),
    version: str = typer.Option("v3", "--version", help="SNMP version: v1, v2c, or v3"),
    community: str = typer.Option(None, "--community", hide_input=True, help="Community string (v1/v2c)"),
    security_level: str = typer.Option("authPriv", "--security-level", help="v3 security level"),
    username: str = typer.Option(None, "--username", "-u", help="SNMPv3 username"),
    auth_protocol: str = typer.Option(None, "--auth-protocol", help="Auth protocol (sha, md5, sha256)"),
    auth_key: str = typer.Option(None, "--auth-key", hide_input=True, help="Authentication key"),
    priv_protocol: str = typer.Option(None, "--priv-protocol", help="Privacy protocol (aes, des)"),
    priv_key: str = typer.Option(None, "--priv-key", hide_input=True, help="Privacy key"),
):
    """Add a new SNMP credential profile (v1 / v2c / v3)."""
    version = (version or "v3").lower().strip()
    if version not in ("v1", "v2c", "v3"):
        rprint("[red]Error:[/red] --version must be v1, v2c, or v3.")
        return

    stored_community = None
    stored_username = ""
    stored_auth_protocol = ""
    stored_auth_key = ""
    stored_priv_protocol = ""
    stored_priv_key = ""
    stored_level = ""

    if version in ("v1", "v2c"):
        community = _prompt_secret("Community", community)
        if not community:
            rprint("[red]Error:[/red] --community is required for v1/v2c profiles.")
            return
        stored_community = encrypt_secret(community)
    else:
        stored_level = _normalize_security_level(security_level)
        if stored_level is None:
            rprint("[red]Error:[/red] --security-level must be authPriv, authNoPriv, or noAuthNoPriv.")
            return
        if not username:
            username = typer.prompt("SNMPv3 username")
        if not username:
            rprint("[red]Error:[/red] username is required for SNMPv3.")
            return
        stored_username = username
        if stored_level in ("authNoPriv", "authPriv"):
            if not auth_protocol:
                auth_protocol = typer.prompt("Auth protocol", default="sha")
            stored_auth_protocol = (auth_protocol or "sha").lower()
            auth_key = _prompt_secret("Authentication key", auth_key)
            if not auth_key:
                rprint("[red]Error:[/red] authentication key is required for this security level.")
                return
            stored_auth_key = encrypt_secret(auth_key) or ""
        if stored_level == "authPriv":
            if not priv_protocol:
                priv_protocol = typer.prompt("Privacy protocol", default="aes")
            stored_priv_protocol = (priv_protocol or "aes").lower()
            priv_key = _prompt_secret("Privacy key", priv_key)
            if not priv_key:
                rprint("[red]Error:[/red] privacy key is required for authPriv.")
                return
            stored_priv_key = encrypt_secret(priv_key) or ""

    db: Session = SessionLocal()
    try:
        existing = db.query(CredentialProfile).filter(CredentialProfile.name == name).first()
        if existing:
            rprint(f"[red]Error:[/red] Profile '{name}' already exists.")
            return

        profile = CredentialProfile(
            name=name,
            description=description or None,
            snmp_version=version,
            security_level=stored_level,
            community=stored_community,
            username=stored_username,
            auth_protocol=stored_auth_protocol,
            auth_key=stored_auth_key,
            priv_protocol=stored_priv_protocol,
            priv_key=stored_priv_key,
        )
        db.add(profile)
        db.commit()
        db.refresh(profile)
        rprint(f"[green]✓[/green] Successfully added SNMP profile: [bold]{name}[/bold] (ID: {profile.id})")
    except Exception as e:
        db.rollback()
        rprint(f"[red]Error adding profile:[/red] {e}")
    finally:
        db.close()


@app.command()
def list_profiles():
    """List credential profiles (never prints keys or community)."""
    db: Session = SessionLocal()
    try:
        profiles = db.query(CredentialProfile).all()
        if not profiles:
            rprint("[yellow]No credential profiles found.[/yellow]")
            return

        table = Table(title="Credential Profiles")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Version")
        table.add_column("Security")
        table.add_column("Username", style="magenta")
        table.add_column("Description")

        for p in profiles:
            table.add_row(
                str(p.id),
                p.name,
                p.snmp_version or "",
                p.security_level or "",
                p.username or "",
                p.description or "",
            )
        console.print(table)
    except Exception as e:
        rprint(f"[red]Error:[/red] {e}")
    finally:
        db.close()


# ============================================================
# Device Commands
# ============================================================

@app.command()
def add_device(
    ip: str = typer.Option(..., prompt=True, help="Device IP address"),
    asset_tag: str = typer.Option("", prompt=True, help="Asset tag (optional, must be unique)"),
    name: str = typer.Option("", prompt=True, help="Device name (optional)"),
    building: str = typer.Option("", prompt=True, help="Building name"),
    location: str = typer.Option("", prompt=True, help="Location (e.g. Closet 1, MDF)"),
    comment: str = typer.Option("", prompt=True, help="Comments or Description"),
    profile: str = typer.Option("", help="SNMP profile name to link (optional)"),
    monitored: bool = typer.Option(True, help="Whether to monitor this device"),
):
    """Add a new device to monitor"""
    db: Session = SessionLocal()
    try:
        # Show available buildings before asking for building
        buildings = db.query(Building).order_by(Building.name).all()
        if buildings:
            rprint("[cyan]Available buildings in reference list:[/cyan]")
            for b in buildings:
                rprint(f"  • {b.name}")
            rprint("")

        # Check for duplicate IP
        if db.query(Device).filter(Device.ip_address == ip).first():
            rprint(f"[red]Error:[/red] Device with IP {ip} already exists.")
            return

        # Check for duplicate Asset Tag (if provided)
        if asset_tag and db.query(Device).filter(Device.asset_tag == asset_tag).first():
            rprint(f"[red]Error:[/red] Device with Asset Tag '{asset_tag}' already exists.")
            return

        profile_id = None
        if profile:
            cred_profile = db.query(CredentialProfile).filter(CredentialProfile.name == profile).first()
            if not cred_profile:
                rprint(f"[red]Error:[/red] SNMP profile '{profile}' not found.")
                return
            profile_id = cred_profile.id

        device = Device(
            ip_address=ip,
            asset_tag=asset_tag or None,
            name=name or None,
            building=building or None,
            location=location or None,
            comment=comment or None,
            credential_profile_id=profile_id,
            monitored=monitored,
        )
        db.add(device)
        db.commit()
        db.refresh(device)

        rprint(f"[green]✓[/green] Device added successfully: [bold]{ip}[/bold] (ID: {device.id})")

    except Exception as e:
        db.rollback()
        rprint(f"[red]Error adding device:[/red] {e}")
    finally:
        db.close()

@app.command(name="list-devices")
def list_devices(
    building: str = typer.Option(None, "--building", "-b", help="Filter by building name"),
    monitored_only: bool = typer.Option(False, "--monitored", help="Show only monitored devices"),
    status: str = typer.Option(None, "--status", "-s", help="Filter by status (up, pre-alarm, down)"),
):
    """List devices with optional filters"""
    db: Session = SessionLocal()
    try:
        query = db.query(Device)

        if building:
            query = query.filter(Device.building.ilike(f"%{building}%"))
        if monitored_only:
            query = query.filter(Device.monitored == True)
        if status:
            query = query.filter(Device.status == status.lower())

        devices = query.order_by(Device.building, Device.name).all()

        if not devices:
            rprint("[yellow]No devices found matching your criteria.[/yellow]")
            return

        table = Table(title="Device List")
        table.add_column("Asset Tag", style="cyan", no_wrap=True)
        table.add_column("IP Address", style="green")
        table.add_column("Name")
        table.add_column("Building")
        table.add_column("Location")
        table.add_column("Vendor")
        table.add_column("Model")
        table.add_column("Comment")
        table.add_column("Status")
        table.add_column("Monitored")

        for d in devices:
            status_color = {
                "up": "green",
                "pre-alarm": "yellow",
                "down": "red",
            }.get(d.status, "white")

            table.add_row(
                d.asset_tag or "-",
                d.ip_address,
                d.name or "-",
                d.building or "-",
                d.location or "-",
                d.vendor or "-",
                d.model or "-",
                d.comment or "-",
                f"[{status_color}]{d.status}[/{status_color}]",
                "Yes" if d.monitored else "No",
            )

        console.print(table)
        rprint(f"\nTotal devices shown: [bold]{len(devices)}[/bold]")

    except Exception as e:
        rprint(f"[red]Error listing devices:[/red] {e}")
    finally:
        db.close()

@app.command(name="show-device")
def show_device(
    identifier: str = typer.Argument(..., help="IP address or Asset Tag of the device"),
):
    """Show detailed information about a single device"""
    db: Session = SessionLocal()
    try:
        # Try to find by IP first, then by Asset Tag
        device = db.query(Device).filter(Device.ip_address == identifier).first()
        if not device:
            device = db.query(Device).filter(Device.asset_tag == identifier).first()

        if not device:
            rprint(f"[red]Device not found with IP or Asset Tag: {identifier}[/red]")
            return

        # Display device details
        rprint(f"\n[bold cyan]Device Details[/bold cyan]")
        rprint(f"{'-'*50}")
        rprint(f"{'Asset Tag:':<20} {device.asset_tag or '-'}")
        rprint(f"{'IP Address:':<20} {device.ip_address}")
        rprint(f"{'Name:':<20} {device.name or '-'}")
        rprint(f"{'Building:':<20} {device.building or '-'}")
        rprint(f"{'Location:':<20} {device.location or '-'}")
        rprint(f"{'Vendor:':<20} {device.vendor or '-'}")
        rprint(f"{'Model:':<20} {device.model or '-'}")
        profile_name = device.credential_profile.name if device.credential_profile else "-"
        rprint(f"{'Profile:':<20} {profile_name}")
        rprint(f"{'Comment:':<20} {device.comment or '-'}")
        rprint(f"{'Status:':<20} {device.status}")
        rprint(f"{'Monitored:':<20} {'Yes' if device.monitored else 'No'}")
        rprint(f"{'Failure Count:':<20} {device.failure_count}")
        rprint(f"{'Response Time:':<20} {device.response_time or '-'} ms")
        rprint(f"{'Last Checked:':<20} {device.last_checked or 'Never'}")
        rprint(f"{'-'*50}\n")

    except Exception as e:
        rprint(f"[red]Error:[/red] {e}")
    finally:
        db.close()

@app.command()
def edit_device(ip: str = typer.Argument(..., help="IP address of the device to edit")):
    """Edit an existing device"""
    db: Session = SessionLocal()
    try:
        device = db.query(Device).filter(Device.ip_address == ip).first()
        if not device:
            rprint(f"[red]Device with IP {ip} not found.[/red]")
            return

        rprint(f"\nEditing device: [bold]{ip}[/bold] (Current values in brackets)")

        # Show available buildings before asking
        buildings = db.query(Building).order_by(Building.name).all()
        if buildings:
            rprint("[cyan]Available buildings in reference list:[/cyan]")
            for b in buildings:
                rprint(f"  • {b.name}")
            rprint("")

        new_asset_tag = typer.prompt("Asset Tag", default=device.asset_tag or "")
        new_name = typer.prompt("Name", default=device.name or "")
        new_building = typer.prompt("Building", default=device.building or "")
        new_location = typer.prompt("Location", default=device.location or "")
        new_comment = typer.prompt("Comment / Description", default=device.comment or "")
        new_monitored = typer.confirm("Monitored?", default=device.monitored)

        # Check for duplicate asset tag (if changed)
        if new_asset_tag and new_asset_tag != device.asset_tag:
            if db.query(Device).filter(Device.asset_tag == new_asset_tag).first():
                rprint(f"[red]Error:[/red] Another device already has Asset Tag '{new_asset_tag}'.")
                return

        device.asset_tag = new_asset_tag or None
        device.name = new_name or None
        device.building = new_building or None
        device.location = new_location or None
        device.comment = new_comment or None
        device.monitored = new_monitored

        db.commit()
        rprint(f"[green]✓[/green] Device {ip} updated successfully.")

    except Exception as e:
        db.rollback()
        rprint(f"[red]Error editing device:[/red] {e}")
    finally:
        db.close()

@app.command(name="search-devices")
def search_devices(
    query: str = typer.Argument(..., help="Search term (matches IP, Name, Asset Tag, Building, or Location)"),
    monitored_only: bool = typer.Option(False, "--monitored", help="Show only monitored devices"),
):
    """Search for devices across multiple fields"""
    db: Session = SessionLocal()
    try:
        q = db.query(Device)

        # Apply search across multiple fields
        search_filter = (
            Device.ip_address.ilike(f"%{query}%") |
            Device.name.ilike(f"%{query}%") |
            Device.asset_tag.ilike(f"%{query}%") |
            Device.building.ilike(f"%{query}%") |
            Device.location.ilike(f"%{query}%") |
            Device.comment.ilike(f"%{query}%")
        )
        q = q.filter(search_filter)

        if monitored_only:
            q = q.filter(Device.monitored == True)

        devices = q.order_by(Device.building, Device.name).all()

        if not devices:
            rprint(f"[yellow]No devices found matching '{query}'.[/yellow]")
            return

        table = Table(title=f"Search Results for '{query}'")
        table.add_column("Asset Tag", style="cyan")
        table.add_column("IP Address", style="green")
        table.add_column("Name")
        table.add_column("Building")
        table.add_column("Location")
        table.add_column("Comment")
        table.add_column("Status")
        table.add_column("Monitored")

        for d in devices:
            status_color = {
                "up": "green",
                "pre-alarm": "yellow",
                "down": "red",
            }.get(d.status, "white")

            table.add_row(
                d.asset_tag or "-",
                d.ip_address,
                d.name or "-",
                d.building or "-",
                d.location or "-",
                d.comment or "-",
                f"[{status_color}]{d.status}[/{status_color}]",
                "Yes" if d.monitored else "No",
            )

        console.print(table)
        rprint(f"\nTotal matches: [bold]{len(devices)}[/bold]")

    except Exception as e:
        rprint(f"[red]Error:[/red] {e}")
    finally:
        db.close()

@app.command()
def delete_device(ip: str = typer.Argument(..., help="IP address of the device to delete")):
    """Delete a device"""
    db: Session = SessionLocal()
    try:
        device = db.query(Device).filter(Device.ip_address == ip).first()
        if not device:
            rprint(f"[red]Device with IP {ip} not found.[/red]")
            return

        confirm = typer.confirm(f"Are you sure you want to delete device {ip}?", default=False)
        if not confirm:
            rprint("[yellow]Deletion cancelled.[/yellow]")
            return

        db.delete(device)
        db.commit()
        rprint(f"[green]✓[/green] Device {ip} has been deleted.")

    except Exception as e:
        db.rollback()
        rprint(f"[red]Error deleting device:[/red] {e}")
    finally:
        db.close()


@app.command()
def snmp_test(
    ip: str = typer.Argument(..., help="IP address of the device to test"),
    profile: str = typer.Option(..., "--profile", "-p", help="Name of the SNMP credential profile"),
):
    """Test SNMP connection and retrieve basic device info"""
    db: Session = SessionLocal()
    try:
        cred_profile = db.query(CredentialProfile).filter(CredentialProfile.name == profile).first()
        if not cred_profile:
            rprint(f"[red]Error:[/red] SNMP profile '{profile}' not found.")
            return

        rprint(f"\n[bold]Testing SNMP on[/bold] [green]{ip}[/green] using profile [cyan]{profile}[/cyan]...\n")

        info = get_device_info(ip, cred_profile)

        table = Table(title="SNMP Results")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="green")

        if "error" in info:
            table.add_row("error", str(info["error"]))
        else:
            table.add_row("sysName", str(info.get("sysName") or ""))
            table.add_row("sysLocation", str(info.get("sysLocation") or ""))
            table.add_row("vendor", str(info.get("vendor") or ""))
            table.add_row("model", str(info.get("model") or ""))
            table.add_row("sysObjectID", str(info.get("sysObjectID") or ""))

        console.print(table)

    except Exception as e:
        rprint(f"[red]SNMP Error:[/red] {e}")
    finally:
        db.close()


@app.command()
def discover(
    target: str = typer.Argument(..., help="IPv4 address or CIDR (max /24)"),
    profile: list[str] = typer.Option(
        None,
        "--profile",
        "-p",
        help="Credential profile name (repeatable, try order)",
    ),
    confirm_public: bool = typer.Option(
        False,
        "--confirm-public",
        help="Required when the target includes public IPv4 space",
    ),
):
    """Probe a subnet with ping then SNMP. Does not write inventory or scan sessions."""
    if not settings.discovery.enabled:
        rprint("[red]Error:[/red] Discovery is disabled.")
        raise typer.Exit(code=1)

    try:
        parsed = parse_scan_target(target)
    except TargetParseError as exc:
        rprint(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2)

    if parsed.contains_public and not confirm_public:
        typer.echo(
            "This address is not RFC1918. Pass --confirm-public to continue.",
            err=True,
        )
        raise typer.Exit(code=2)

    profile_names = profile or []
    ping_timeout, ping_conc, snmp_timeout, snmp_conc = clamp_scan_options()
    db: Session = SessionLocal()
    try:
        profiles: list[CredentialProfile] = []
        for name in profile_names:
            cred = (
                db.query(CredentialProfile)
                .filter(CredentialProfile.name == name)
                .first()
            )
            if not cred:
                rprint(f"[red]Error:[/red] SNMP profile '{name}' not found.")
                raise typer.Exit(code=1)
            db.expunge(cred)
            profiles.append(cred)
        managed = {d.ip_address: d.id for d in db.query(Device).all()}
    finally:
        db.close()

    hosts = [str(ip) for ip in parsed.hosts]
    rprint(
        f"[bold]Discover[/bold] {target} "
        f"({len(hosts)} host{'s' if len(hosts) != 1 else ''}, "
        f"profiles: {', '.join(profile_names) if profile_names else 'none'})"
    )

    rows = asyncio.run(
        probe_hosts(
            hosts,
            profiles,
            ping_timeout=ping_timeout,
            ping_concurrency=ping_conc,
            snmp_timeout=snmp_timeout,
            snmp_concurrency=snmp_conc,
            managed=managed,
        )
    )

    if not rows:
        rprint("[yellow]No live or managed hosts found.[/yellow]")
        return

    table = Table(title="Discover results")
    table.add_column("IP", style="green")
    table.add_column("Ping RTT")
    table.add_column("SNMP")
    table.add_column("Name")
    table.add_column("Location")
    table.add_column("Vendor")
    table.add_column("Model")
    table.add_column("Already managed")

    for row in rows:
        rtt = row.get("ping_rtt_ms")
        rtt_text = f"{rtt:.1f} ms" if rtt is not None else "-"
        table.add_row(
            row["ip"],
            rtt_text,
            str(row.get("snmp_status") or ""),
            row.get("name") or "-",
            row.get("location") or "-",
            row.get("vendor") or "-",
            row.get("model") or "-",
            "yes" if row.get("already_managed") else "no",
        )
    console.print(table)

# ============================================================
# Building Management Commands
# ============================================================

@app.command()
def list_buildings():
    """List all managed building names"""
    db: Session = SessionLocal()
    try:
        buildings = db.query(Building).order_by(Building.name).all()
        if not buildings:
            rprint("[yellow]No buildings defined yet.[/yellow]")
            return

        table = Table(title="Managed Buildings")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Description")

        for b in buildings:
            table.add_row(str(b.id), b.name, b.description or "")
        console.print(table)
    except Exception as e:
        rprint(f"[red]Error:[/red] {e}")
    finally:
        db.close()


@app.command()
def add_building(
    name: str = typer.Argument(..., help="Building name"),
    description: str = typer.Option("", help="Optional description"),
):
    """Add a new building to the reference list"""
    db: Session = SessionLocal()
    try:
        existing = db.query(Building).filter(Building.name == name).first()
        if existing:
            rprint(f"[red]Error:[/red] Building '{name}' already exists.")
            return

        building = Building(name=name, description=description or None)
        db.add(building)
        db.commit()
        rprint(f"[green]✓[/green] Building added: [bold]{name}[/bold]")
    except Exception as e:
        db.rollback()
        rprint(f"[red]Error:[/red] {e}")
    finally:
        db.close()


@app.command()
def remove_building(
    name: str = typer.Argument(..., help="Building name to remove")
):
    """Remove a building from the reference list"""
    db: Session = SessionLocal()
    try:
        building = db.query(Building).filter(Building.name == name).first()
        if not building:
            rprint(f"[red]Error:[/red] Building '{name}' not found.")
            return

        # Check if any devices use it
        used = db.query(Device).filter(Device.building == name).count()
        if used > 0:
            rprint(f"[yellow]Warning:[/yellow] {used} devices use this building. Removal will not affect existing devices.")

        confirm = typer.confirm(f"Remove building '{name}'?", default=False)
        if not confirm:
            return

        db.delete(building)
        db.commit()
        rprint(f"[green]✓[/green] Building '{name}' removed.")
    except Exception as e:
        db.rollback()
        rprint(f"[red]Error:[/red] {e}")
    finally:
        db.close()

## admin user section
@app.command(name="create-admin")
def create_admin(
    username: str = typer.Option(..., prompt=True),
    password: str = typer.Option(..., prompt=True, hide_input=True),
):
    """Create the first admin user"""
    from passlib.context import CryptContext
    from inform.core.models import User

    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    def get_password_hash(password: str) -> str:
        return pwd_context.hash(password)

    db: Session = SessionLocal()
    try:
        existing = db.query(User).filter(User.username == username).first()
        if existing:
            rprint(f"[red]Error:[/red] User '{username}' already exists.")
            return

        hashed_password = get_password_hash(password)
        user = User(username=username, hashed_password=hashed_password)
        db.add(user)
        db.commit()

        rprint(f"[green]✓[/green] Admin user '{username}' created successfully.")

    except Exception as e:
        db.rollback()
        rprint(f"[red]Error creating admin user:[/red] {e}")
    finally:
        db.close()

if __name__ == "__main__":
    app()
