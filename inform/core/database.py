import os
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from inform.core.config import settings

# ========================
# Data Directory Setup
# ========================
DATA_DIR = Path(__file__).parent.parent.parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_URL = f"sqlite:///{DATA_DIR}/inform.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def ensure_db_permissions():
    """Ensure the database file and data directory have correct permissions."""
    db_path = DATA_DIR / "inform.db"

    if not db_path.exists():
        return

    try:
        # Set directory permissions
        os.chmod(DATA_DIR, 0o775)

        # Set database file permissions
        os.chmod(db_path, 0o664)

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


def init_db():
    """Initialize the database and set correct permissions."""
    # Models must be imported so they register on Base.metadata.
    from inform.core import models as _models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    ensure_db_permissions()
    print(f"Database initialized at: {DATA_DIR / 'inform.db'}")


# ========================
# Auto-fix permissions on import
# ========================
ensure_db_permissions()
