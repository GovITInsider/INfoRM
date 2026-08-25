"""CLI commands for YAML inventory export/import."""

from pathlib import Path

import typer
from rich import print as rprint
from rich.console import Console
from sqlalchemy.orm import Session

from inform.core.database import SessionLocal

console = Console()


def register_inventory(app: typer.Typer) -> None:
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
