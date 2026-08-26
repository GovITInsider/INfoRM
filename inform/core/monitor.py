import time
import signal
import logging
import sys
import shutil
from datetime import datetime
from icmplib import ping
from sqlalchemy.orm import Session

from inform.core.database import SessionLocal, ensure_db_permissions, ensure_schema
from inform.core.models import Device, AlarmEvent
from inform.core.config import settings

# Ensure database has correct permissions on startup
ensure_db_permissions()

# -----------------------------
# Logging Setup
# -----------------------------
logger = logging.getLogger("inform.monitor")
logger.setLevel(getattr(logging, settings.general.log_level.upper(), logging.INFO))

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

if settings.logging.log_file:
    file_handler = logging.FileHandler(settings.logging.log_file)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)


# -----------------------------
# Graceful Shutdown
# -----------------------------
shutdown_requested = False

def signal_handler(signum, frame):
    global shutdown_requested
    logger.info("Shutdown signal received. Exiting gracefully...")
    shutdown_requested = True

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

import subprocess
import re

def ping_device(ip: str, timeout: float = 2.0) -> tuple[bool, float | None]:
    try:
        ping_cmd = shutil.which("ping") or "/usr/bin/ping"

        result = subprocess.run(
            [ping_cmd, "-c", "1", "-W", str(int(timeout)), ip],
            capture_output=True,
            text=True,
            timeout=timeout + 1
        )

        if result.returncode != 0:
            return False, None

        # Try to extract response time from ping output
        match = re.search(r'time[=<]([\d.]+)\s*ms', result.stdout)
        rtt = float(match.group(1)) if match else None

        return True, rtt

    except subprocess.TimeoutExpired:
        return False, None
    except Exception as e:
        logger.error(f"Unexpected error pinging {ip}: {e}")
        return False, None

def log_alarm_event(device: Device, event_type: str):
    db: Session = SessionLocal()
    try:
        event = AlarmEvent(
            device_id=device.id,
            event_type=event_type,
            failure_count=device.failure_count,
            device_ip=device.ip_address,
            device_name=device.name,
            building=device.building,
            location=device.location,
        )
        db.add(event)
        db.commit()
        logger.info(f"{event_type} logged for {device.ip_address}")
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to log {event_type} for {device.ip_address}: {e}")
    finally:
        db.close()


def process_device(device: Device, is_up: bool, response_time: float | None):
    db: Session = SessionLocal()
    try:
        db_device = db.query(Device).filter(Device.id == device.id).first()
        if not db_device:
            return

        previous_status = db_device.status
        threshold = settings.monitoring.countbeforealarm

        if is_up:
            db_device.status = "up"
            db_device.failure_count = 0
            db_device.response_time = response_time

            if previous_status == "down" and db_device.monitored:
                log_alarm_event(db_device, "CLEARED")
        else:
            db_device.failure_count += 1
            db_device.response_time = None

            if db_device.failure_count >= threshold:
                new_status = "down"
            else:
                new_status = "pre-alarm"

            if new_status == "down" and previous_status != "down" and db_device.monitored:
                log_alarm_event(db_device, "ALARM")

            db_device.status = new_status

        from datetime import datetime, timezone
        db_device.last_checked = datetime.now(timezone.utc)
        db.commit()

    except Exception as e:
        db.rollback()
        logger.error(f"Error processing {device.ip_address}: {e}")
    finally:
        db.close()

def run_monitoring_cycle():
    db: Session = SessionLocal()
    try:
        devices = db.query(Device).all()
        logger.info(f"Monitoring {len(devices)} devices...")

        for device in devices:
            if shutdown_requested:
                break

            try:
                is_up, rtt = ping_device(device.ip_address)
                #logger.info(f"{device.ip_address} → is_up={is_up}, rtt={rtt}")   # ← TEMP DEBUG LINE
                process_device(device, is_up, rtt)
            except Exception as e:
                logger.error(f"Error pinging {device.ip_address}: {e}")

    except Exception as e:
        logger.error(f"Error in monitoring cycle: {e}")
    finally:
        db.close()

def main():
    logger.info("INfoRM Monitor started")
    ensure_schema()

    while not shutdown_requested:
        try:
            run_monitoring_cycle()
        except Exception as e:
            logger.error(f"Unexpected error in main loop: {e}")

        if not shutdown_requested:
            time.sleep(settings.monitoring.poll_interval_seconds)

    logger.info("INfoRM Monitor stopped cleanly")


if __name__ == "__main__":
    main()
