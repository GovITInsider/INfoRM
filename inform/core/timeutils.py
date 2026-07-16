from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from inform.core.config import settings

# Default to America/Los_Angeles – change in config if needed
LOCAL_TZ = ZoneInfo(getattr(settings.web, "local_timezone", "America/Los_Angeles"))

def to_local(dt: datetime | None) -> datetime | None:
    """Convert a UTC datetime to local time."""
    if dt is None:
        return None

    # Handle both naive and aware datetimes
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(LOCAL_TZ)
