import logging
import os
from pathlib import Path
from sqlalchemy import create_engine, event, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker, declarative_base

from inform.core.config import settings

logger = logging.getLogger("inform.database")

# ========================
# Data Directory Setup
# ========================
DATA_DIR = Path(__file__).parent.parent.parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_URL = f"sqlite:///{DATA_DIR}/inform.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False, "timeout": 30},
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


@event.listens_for(engine, "connect")
def _sqlite_connect(dbapi_connection, connection_record):
    # Non-legacy sqlite transactions: we emit BEGIN IMMEDIATE (see _sqlite_begin).
    dbapi_connection.isolation_level = None
    cur = dbapi_connection.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA busy_timeout=30000")
    # Do not enable PRAGMA foreign_keys=ON. AlarmEvent.device_id has no
    # ON DELETE; delete_device succeeds today only because FKs default off.
    cur.close()


@event.listens_for(engine, "begin")
def _sqlite_begin(conn):
    conn.exec_driver_sql("BEGIN IMMEDIATE")


def ensure_db_permissions():
    """Ensure the database file and data directory have correct permissions."""
    db_path = DATA_DIR / "inform.db"

    if not db_path.exists():
        return

    try:
        # Set directory permissions
        os.chmod(DATA_DIR, 0o775)

        # Set database file permissions (group inform only; secrets live here)
        os.chmod(db_path, 0o640)

        # Only try to change ownership if running as root
        if os.getuid() == 0:
            try:
                import pwd
                inform_uid = pwd.getpwnam("inform").pw_uid
                os.chown(db_path, inform_uid, -1)
                os.chown(DATA_DIR, inform_uid, -1)
            except (KeyError, PermissionError):
                pass  # inform user doesn't exist or no permission to chown

    except PermissionError:
        pass  # Running without sufficient permissions


def _columns(conn, table: str) -> set[str]:
    rows = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
    return {row[1] for row in rows}


def _add_column(conn, table: str, column: str, decl: str) -> None:
    if column in _columns(conn, table):
        return
    try:
        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {decl}"))
        logger.info("%s.%s added", table, column)
    except OperationalError as e:
        if "duplicate column name" not in str(e).lower():
            raise


def migrate_schema() -> None:
    with engine.begin() as conn:
        _add_column(conn, "devices", "vendor", "VARCHAR(100)")
        _add_column(conn, "devices", "model", "VARCHAR(100)")
        _add_column(conn, "devices", "sys_object_id", "VARCHAR(256)")
        _add_column(conn, "credential_profiles", "snmp_version", "VARCHAR(10) DEFAULT 'v3'")
        _add_column(conn, "credential_profiles", "security_level", "VARCHAR(20) DEFAULT 'authPriv'")
        _add_column(conn, "credential_profiles", "community", "TEXT")
        _add_column(conn, "scan_sessions", "timeout_requested", "BOOLEAN DEFAULT 0")
        conn.execute(text(
            "UPDATE credential_profiles SET snmp_version = 'v3' "
            "WHERE snmp_version IS NULL OR snmp_version = ''"
        ))
        conn.execute(text(
            "UPDATE credential_profiles SET security_level = 'authPriv' "
            "WHERE security_level IS NULL"
        ))


def ensure_schema() -> None:
    from inform.core import models as _models  # noqa: F401 — register metadata
    from inform.core.secrets import encrypt_legacy_secrets

    Base.metadata.create_all(bind=engine)
    migrate_schema()
    encrypt_legacy_secrets()
    ensure_db_permissions()


def init_db():
    """Initialize the database and set correct permissions."""
    ensure_schema()
    ensure_db_permissions()
    print(f"Database initialized at: {DATA_DIR / 'inform.db'}")


# ========================
# Auto-fix permissions on import
# ========================
ensure_db_permissions()
