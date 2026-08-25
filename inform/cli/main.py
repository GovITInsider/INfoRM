import warnings
from pathlib import Path
from sqlalchemy.exc import SAWarning

# Suppress the "declarative base already contains" warning
warnings.filterwarnings("ignore", category=SAWarning)

import typer
from rich import print as rprint
from rich.table import Table
from rich.console import Console
from sqlalchemy.orm import Session

from inform.core.database import SessionLocal
from inform.core.models import CredentialProfile, Device
from inform.core.config import settings
from inform.snmp.client import get_device_info
from inform.core.models import CredentialProfile, Device, Building



app = typer.Typer(
    name="inform",
    help="INfoRM - Network Reachability Monitor (Python version)",
    add_completion=False,
)
console = Console()


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

@app.command()
def add_profile(
    name: str = typer.Option(..., prompt=True, help="Profile name (e.g. cisco, f5)"),
    description: str = typer.Option("", prompt=True, help="Optional description"),
    username: str = typer.Option(..., prompt=True, help="SNMPv3 username"),
    auth_protocol: str = typer.Option("sha", prompt=True, help="Auth protocol (sha, md5, none)"),
    auth_key: str = typer.Option(..., prompt=True, hide_input=True, help="Authentication key"),
    priv_protocol: str = typer.Option("aes", prompt=True, help="Privacy protocol (aes, des, none)"),
    priv_key: str = typer.Option(..., prompt=True, hide_input=True, help="Privacy key"),
):
    """Add a new SNMPv3 credential profile"""
    db: Session = SessionLocal()
    try:
        existing = db.query(CredentialProfile).filter(CredentialProfile.name == name).first()
        if existing:
            rprint(f"[red]Error:[/red] Profile '{name}' already exists.")
            return

        profile = CredentialProfile(
            name=name,
            description=description or None,
            username=username,
            auth_protocol=auth_protocol.lower(),
            auth_key=auth_key,
            priv_protocol=priv_protocol.lower(),
            priv_key=priv_key,
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
    """List all SNMPv3 credential profiles"""
    db: Session = SessionLocal()
    try:
        profiles = db.query(CredentialProfile).all()
        if not profiles:
            rprint("[yellow]No credential profiles found.[/yellow]")
            return

        table = Table(title="SNMPv3 Credential Profiles")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Username", style="magenta")
        table.add_column("Auth", style="yellow")
        table.add_column("Priv", style="yellow")
        table.add_column("Description")

        for p in profiles:
            table.add_row(str(p.id), p.name, p.username, p.auth_protocol, p.priv_protocol, p.description or "")
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
    """Test SNMPv3 connection and retrieve basic device info"""
    db: Session = SessionLocal()
    try:
        cred_profile = db.query(CredentialProfile).filter(CredentialProfile.name == profile).first()
        if not cred_profile:
            rprint(f"[red]Error:[/red] SNMP profile '{profile}' not found.")
            return

        rprint(f"\n[bold]Testing SNMPv3 on[/bold] [green]{ip}[/green] using profile [cyan]{profile}[/cyan]...\n")

        info = get_device_info(ip, cred_profile)

        table = Table(title="SNMP Results")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="green")

        for key, value in info.items():
            table.add_row(key, str(value))

        console.print(table)

    except Exception as e:
        rprint(f"[red]SNMP Error:[/red] {e}")
    finally:
        db.close()

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


# ============================================================
# Inventory export / import
# ============================================================

@app.command(name="export-inventory")
def export_inventory_cmd(
    output: Path = typer.Option(
        None,
        "--output",
        "-o",
        help="Write YAML to this file (default: stdout)",
    ),
):
    """Export buildings and devices to a YAML inventory file."""
    from inform.core.inventory import build_inventory, dump_inventory_yaml

    db: Session = SessionLocal()
    try:
        yaml_text = dump_inventory_yaml(build_inventory(db))
        if output:
            output.write_text(yaml_text, encoding="utf-8")
            rprint(f"[green]✓[/green] Inventory written to [bold]{output}[/bold]")
        else:
            console.print(yaml_text, end="")
    except Exception as e:
        rprint(f"[red]Error exporting inventory:[/red] {e}")
        raise typer.Exit(code=1)
    finally:
        db.close()


@app.command(name="import-inventory")
def import_inventory_cmd(
    path: Path = typer.Argument(..., exists=True, readable=True, help="YAML inventory file"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Validate and report changes without writing"),
):
    """Import buildings and devices from a YAML inventory file.

    Existing building names and device IPs are skipped (same as add-building / add-device).
    """
    from inform.core.inventory import load_inventory_yaml, import_inventory

    try:
        inventory = load_inventory_yaml(path.read_text(encoding="utf-8"))
    except Exception as e:
        rprint(f"[red]Invalid inventory file:[/red] {e}")
        raise typer.Exit(code=1)

    db: Session = SessionLocal()
    try:
        stats = import_inventory(db, inventory, dry_run=dry_run)
        prefix = "[yellow]Dry run[/yellow] — " if dry_run else "[green]✓[/green] "
        rprint(f"{prefix}Buildings added: [bold]{stats['buildings_added']}[/bold], skipped: {stats['buildings_skipped']}")
        rprint(f"{prefix}Devices added: [bold]{stats['devices_added']}[/bold], skipped: {stats['devices_skipped']}")
    except Exception as e:
        db.rollback()
        rprint(f"[red]Error importing inventory:[/red] {e}")
        raise typer.Exit(code=1)
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
