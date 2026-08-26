"""On-demand ping-then-SNMP scan orchestrator.

Runs as an in-process asyncio task (inform-web). One scan at a time.
CLI `discover` uses probe_hosts() and must not write scan_sessions.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, Awaitable, Callable, Sequence

from pysnmp.hlapi.v3arch.asyncio import SnmpEngine
from sqlalchemy import text
from sqlalchemy.orm import Session

from inform.core.config import settings
from inform.core.database import SessionLocal, engine
from inform.core.models import CredentialProfile, Device, ScanResult, ScanSession
from inform.snmp.client import SnmpErrorKind, SnmpIdentity, identify
from inform.snmp.ping import ping_one
from inform.snmp.targets import parse_scan_target

logger = logging.getLogger("inform.discover")

_current_task: asyncio.Task | None = None
_current_session_id: int | None = None

_MAX_PING_TIMEOUT = 3
_MAX_SNMP_TIMEOUT = 5
_WATCHDOG_CAP_SECONDS = 20 * 60
_WRITER_BATCH = 8
_ACTIVE = ("running", "cancelling")

Worker = Callable[[Any], Awaitable[None]]


class ScanError(Exception):
    """Base class for scan start failures."""


class ScanAlreadyRunning(ScanError):
    def __init__(self, session_id: int):
        self.session_id = session_id
        super().__init__(f"Scan {session_id} is already running")


class UnsavedReviewError(ScanError):
    def __init__(self, session_id: int):
        self.session_id = session_id
        super().__init__(f"Session {session_id} has unsaved review rows")


class PublicSpaceError(ScanError):
    """Target includes public IPv4 space and confirm_public was not set."""


class DiscoveryDisabledError(ScanError):
    """discovery.enabled is false."""


def clamp_scan_options(
    ping_timeout_seconds: int | None = None,
    ping_concurrency: int | None = None,
    snmp_timeout_seconds: int | None = None,
    snmp_concurrency: int | None = None,
) -> tuple[int, int, int, int]:
    d = settings.discovery

    def _clamp(value: int | None, default: int, lo: int, hi: int) -> int:
        n = default if value is None else int(value)
        return max(lo, min(n, hi))

    ping_timeout = _clamp(
        ping_timeout_seconds, d.default_ping_timeout_seconds, 1, _MAX_PING_TIMEOUT
    )
    ping_conc = _clamp(
        ping_concurrency, d.default_ping_concurrency, 1, d.max_ping_concurrency
    )
    snmp_timeout = _clamp(
        snmp_timeout_seconds, d.default_snmp_timeout_seconds, 1, _MAX_SNMP_TIMEOUT
    )
    snmp_conc = _clamp(
        snmp_concurrency, d.default_snmp_concurrency, 1, d.max_snmp_concurrency
    )
    return ping_timeout, ping_conc, snmp_timeout, snmp_conc


def _normalize_profile_ids(profile_ids: Sequence[int] | None) -> list[int]:
    out: list[int] = []
    for raw in profile_ids or ():
        try:
            pid = int(raw)
        except (TypeError, ValueError):
            continue
        if pid > 0 and pid not in out:
            out.append(pid)
    return out


def _unsaved_on_conn(conn, session_id: int) -> bool:
    row = conn.execute(
        text(
            """
            SELECT sr.id FROM scan_results sr
            WHERE sr.session_id = :sid
              AND (sr.already_managed = 0 OR sr.already_managed IS NULL)
              AND NOT EXISTS (
                  SELECT 1 FROM devices d WHERE d.ip_address = sr.ip_address
              )
            LIMIT 1
            """
        ),
        {"sid": session_id},
    ).fetchone()
    return row is not None


def begin_scan(
    target: str,
    *,
    profile_ids: Sequence[int] | None = None,
    default_building: str | None = None,
    ping_timeout_seconds: int | None = None,
    ping_concurrency: int | None = None,
    snmp_timeout_seconds: int | None = None,
    snmp_concurrency: int | None = None,
    confirm_public: bool = False,
    discard_previous: bool = False,
    started_by: str | None = None,
) -> int:
    """Create a running scan_sessions row under the engine-wide BEGIN IMMEDIATE lock."""
    if not settings.discovery.enabled:
        raise DiscoveryDisabledError("Discovery is disabled")

    parsed = parse_scan_target(target)
    if parsed.contains_public and not confirm_public:
        raise PublicSpaceError(
            "This address is not RFC1918. Check “scan public space” to continue."
        )

    ping_timeout, ping_conc, snmp_timeout, snmp_conc = clamp_scan_options(
        ping_timeout_seconds,
        ping_concurrency,
        snmp_timeout_seconds,
        snmp_concurrency,
    )
    ids = _normalize_profile_ids(profile_ids)
    raw_target = (target or "").strip()

    with engine.begin() as conn:
        running = conn.execute(
            text(
                "SELECT id FROM scan_sessions "
                "WHERE status IN ('running', 'cancelling') LIMIT 1"
            )
        ).fetchone()
        if running:
            raise ScanAlreadyRunning(int(running[0]))

        latest = conn.execute(
            text("SELECT id, status FROM scan_sessions ORDER BY id DESC LIMIT 1")
        ).fetchone()
        if latest is not None:
            latest_id, latest_status = int(latest[0]), latest[1]
            if latest_status in ("completed", "cancelled", "failed"):
                if _unsaved_on_conn(conn, latest_id) and not discard_previous:
                    raise UnsavedReviewError(latest_id)

        conn.execute(
            text(
                """
                INSERT INTO scan_sessions (
                    target, default_building, profile_ids_json,
                    ping_timeout_seconds, ping_concurrency,
                    snmp_timeout_seconds, snmp_concurrency,
                    status, total_hosts, pinged_count, live_count, snmp_done_count,
                    cancel_requested, timeout_requested, started_by, started_at
                ) VALUES (
                    :target, :default_building, :profile_ids_json,
                    :ping_timeout, :ping_conc, :snmp_timeout, :snmp_conc,
                    'running', :total_hosts, 0, 0, 0,
                    0, 0, :started_by, :started_at
                )
                """
            ),
            {
                "target": raw_target,
                "default_building": default_building,
                "profile_ids_json": json.dumps(ids),
                "ping_timeout": ping_timeout,
                "ping_conc": ping_conc,
                "snmp_timeout": snmp_timeout,
                "snmp_conc": snmp_conc,
                "total_hosts": len(parsed.hosts),
                "started_by": started_by,
                "started_at": datetime.utcnow(),
            },
        )
        new_id = int(conn.execute(text("SELECT last_insert_rowid()")).scalar())
        conn.execute(
            text("DELETE FROM scan_results WHERE session_id != :id"),
            {"id": new_id},
        )
        conn.execute(
            text("DELETE FROM scan_sessions WHERE id != :id"),
            {"id": new_id},
        )
        return new_id


def start_scan_task(session_id: int) -> None:
    global _current_task, _current_session_id
    if _current_task is not None and not _current_task.done():
        raise ScanAlreadyRunning(_current_session_id or session_id)
    task = asyncio.create_task(run_scan(session_id), name=f"inform-scan-{session_id}")
    _current_task = task
    _current_session_id = session_id
    task.add_done_callback(lambda t, sid=session_id: _on_scan_done(t, sid))
    asyncio.create_task(
        _watchdog(session_id, task),
        name=f"inform-scan-watchdog-{session_id}",
    )


def _on_scan_done(task: asyncio.Task, session_id: int) -> None:
    """Backstop if run_scan's finally did not run (should be rare)."""
    global _current_task, _current_session_id
    try:
        if not task.cancelled():
            exc = task.exception()
            if exc is not None:
                _mark_session_failed_if_unfinished(
                    session_id, f"scan task crashed: {type(exc).__name__}"
                )
    except asyncio.CancelledError:
        pass
    except Exception:
        logger.debug("scan done callback failed", exc_info=True)
    if _current_task is task:
        _current_task = None
        if _current_session_id == session_id:
            _current_session_id = None


async def _watchdog(session_id: int, task: asyncio.Task) -> None:
    session = _load_session(session_id)
    if session is None:
        return
    limit_s = _watchdog_limit_seconds(session)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + limit_s
    try:
        while not task.done():
            remaining = deadline - loop.time()
            if remaining <= 0:
                _set_timeout_requested(session_id)
                if not task.done():
                    task.cancel()
                return
            await asyncio.wait({task}, timeout=min(remaining, 1.0))
    except asyncio.CancelledError:
        return


def _watchdog_limit_seconds(session: ScanSession) -> float:
    try:
        n_profiles = len(json.loads(session.profile_ids_json or "[]"))
    except (TypeError, json.JSONDecodeError):
        n_profiles = 0
    ping_c = max(int(session.ping_concurrency or 1), 1)
    snmp_c = max(int(session.snmp_concurrency or 1), 1)
    ping_to = float(session.ping_timeout_seconds or 1)
    snmp_to = float(session.snmp_timeout_seconds or 2)
    total = max(int(session.total_hosts or 0), 1)
    estimated = total * ping_to / ping_c + total * n_profiles * snmp_to / snmp_c + 60.0
    configured = float(settings.discovery.scan_max_runtime_seconds)
    return min(max(configured, estimated), _WATCHDOG_CAP_SECONDS)


def request_cancel(session_id: int | None = None) -> None:
    """Operator cancel: set flags, cancel the in-process task, or mark orphaned."""
    sid = _current_session_id if session_id is None else session_id
    if sid is None:
        return
    task_live = (
        _current_task is not None
        and not _current_task.done()
        and _current_session_id == sid
    )
    db = SessionLocal()
    try:
        row = db.query(ScanSession).filter(ScanSession.id == sid).first()
        if row is None or row.status not in _ACTIVE:
            return
        if not task_live:
            row.status = "failed"
            row.error_message = "orphaned; no in-process task"
            row.finished_at = datetime.utcnow()
            db.commit()
            return
        row.cancel_requested = True
        row.status = "cancelling"
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
    if task_live and _current_task is not None and not _current_task.done():
        _current_task.cancel()


def fail_interrupted_sessions(message: str) -> None:
    db = SessionLocal()
    try:
        rows = (
            db.query(ScanSession)
            .filter(ScanSession.status.in_(("running", "cancelling")))
            .all()
        )
        now = datetime.utcnow()
        for row in rows:
            row.status = "failed"
            row.error_message = message
            row.finished_at = now
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


async def cancel_current_scan() -> None:
    """Web shutdown: request cancel and await the task; finally writes cancelled."""
    task = _current_task
    sid = _current_session_id
    if task is None or task.done():
        return
    if sid is not None:
        db = SessionLocal()
        try:
            row = db.query(ScanSession).filter(ScanSession.id == sid).first()
            if row is not None and row.status in _ACTIVE:
                row.cancel_requested = True
                row.status = "cancelling"
                db.commit()
        except Exception:
            db.rollback()
            logger.debug("shutdown cancel flag write failed", exc_info=True)
        finally:
            db.close()
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


def _load_session(session_id: int) -> ScanSession | None:
    db = SessionLocal()
    try:
        row = db.query(ScanSession).filter(ScanSession.id == session_id).first()
        if row is not None:
            db.expunge(row)
        return row
    finally:
        db.close()


def _session_flags(session_id: int) -> tuple[bool, bool, str | None]:
    db = SessionLocal()
    try:
        row = db.query(ScanSession).filter(ScanSession.id == session_id).first()
        if row is None:
            return False, False, None
        return bool(row.cancel_requested), bool(row.timeout_requested), row.status
    finally:
        db.close()


def _should_stop(session_id: int) -> bool:
    cancel, timeout, status = _session_flags(session_id)
    return cancel or timeout or status not in _ACTIVE


def _set_timeout_requested(session_id: int) -> None:
    db = SessionLocal()
    try:
        row = db.query(ScanSession).filter(ScanSession.id == session_id).first()
        if row is None:
            return
        row.timeout_requested = True
        db.commit()
    except Exception:
        db.rollback()
        logger.error("failed to set timeout_requested session=%s", session_id)
    finally:
        db.close()


def _mark_session_failed_if_unfinished(session_id: int | None, message: str) -> None:
    if session_id is None:
        return
    db = SessionLocal()
    try:
        row = db.query(ScanSession).filter(ScanSession.id == session_id).first()
        if row is None or row.status not in _ACTIVE:
            return
        row.status = "failed"
        row.error_message = message[:500]
        row.finished_at = datetime.utcnow()
        db.commit()
    except Exception:
        db.rollback()
        logger.error("failed to mark session %s failed", session_id)
    finally:
        db.close()


def _finalize_session(session_id: int) -> None:
    cancel, timeout, status = _session_flags(session_id)
    if timeout:
        new_status = "failed"
    elif cancel:
        new_status = "cancelled"
    elif status in _ACTIVE:
        new_status = "completed"
    else:
        return
    db = SessionLocal()
    try:
        row = db.query(ScanSession).filter(ScanSession.id == session_id).first()
        if row is None:
            return
        if timeout:
            row.status = "failed"
            row.error_message = "timed out"
        elif cancel:
            row.status = "cancelled"
            row.error_message = None
        elif row.status in _ACTIVE:
            row.status = "completed"
            row.error_message = None
        else:
            return
        row.finished_at = datetime.utcnow()
        db.commit()
        logger.info(
            "scan %s session=%s live=%s snmp_done=%s pinged=%s",
            new_status,
            session_id,
            row.live_count,
            row.snmp_done_count,
            row.pinged_count,
        )
    except Exception:
        db.rollback()
        logger.error("failed to finalize session %s", session_id)
    finally:
        db.close()


def _managed_ip_map() -> dict[str, int]:
    db = SessionLocal()
    try:
        rows = db.query(Device.id, Device.ip_address).all()
        return {ip: did for did, ip in rows}
    finally:
        db.close()


def _load_profiles(profile_ids: Sequence[int]) -> list[CredentialProfile]:
    if not profile_ids:
        return []
    db = SessionLocal()
    try:
        found = {
            p.id: p
            for p in db.query(CredentialProfile)
            .filter(CredentialProfile.id.in_(list(profile_ids)))
            .all()
        }
        profiles: list[CredentialProfile] = []
        for pid in profile_ids:
            profile = found.get(pid)
            if profile is None:
                continue
            db.expunge(profile)
            profiles.append(profile)
        return profiles
    finally:
        db.close()


def _parse_profile_ids(raw: str | None) -> list[int]:
    try:
        data = json.loads(raw or "[]")
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    return _normalize_profile_ids(data)


def _snmp_status_from_error(err: SnmpErrorKind | None) -> str:
    if err == SnmpErrorKind.AUTH:
        return "auth_fail"
    return "no_snmp"


async def _run_batches(
    items: Sequence[Any],
    concurrency: int,
    worker: Worker,
    session_id: int | None,
) -> None:
    """At most `concurrency` in-flight. Check cancel before starting a new slot."""
    pending: set[asyncio.Task] = set()
    it = iter(items)
    conc = max(int(concurrency), 1)

    def _stop() -> bool:
        return session_id is not None and _should_stop(session_id)

    def _try_start() -> bool:
        if _stop():
            return False
        try:
            item = next(it)
        except StopIteration:
            return False
        pending.add(asyncio.create_task(worker(item)))
        return True

    try:
        while True:
            while len(pending) < conc:
                if not _try_start():
                    break
            if not pending:
                return
            done, pending = await asyncio.wait(
                pending, return_when=asyncio.FIRST_COMPLETED
            )
            for task in done:
                if task.cancelled():
                    continue
                exc = task.exception()
                if exc is not None:
                    logger.debug("scan worker failed: %s", type(exc).__name__)
            if _stop():
                if pending:
                    await asyncio.wait(pending)
                return
    except asyncio.CancelledError:
        if pending:
            await asyncio.shield(asyncio.wait(pending))
        raise


def _flush_writer(db: Session, session_id: int, batch: list[dict]) -> None:
    if not batch:
        return
    sess = db.query(ScanSession).filter(ScanSession.id == session_id).first()
    if sess is None:
        return
    for item in batch:
        op = item.get("op")
        if op == "ping":
            sess.pinged_count = (sess.pinged_count or 0) + 1
            if item.get("ping_ok"):
                sess.live_count = (sess.live_count or 0) + 1
            if item.get("insert"):
                db.add(
                    ScanResult(
                        session_id=session_id,
                        ip_address=item["ip"],
                        already_managed=bool(item.get("already_managed")),
                        managed_device_id=item.get("managed_device_id"),
                        ping_ok=bool(item.get("ping_ok")),
                        ping_rtt_ms=item.get("ping_rtt_ms"),
                        snmp_status=item.get("snmp_status") or "no_snmp",
                    )
                )
                db.flush()
        elif op == "snmp":
            sess.snmp_done_count = (sess.snmp_done_count or 0) + 1
            row = (
                db.query(ScanResult)
                .filter(
                    ScanResult.session_id == session_id,
                    ScanResult.ip_address == item["ip"],
                )
                .first()
            )
            if row is None:
                continue
            row.snmp_status = item.get("snmp_status") or "no_snmp"
            row.name = item.get("name")
            row.location = item.get("location")
            row.vendor = item.get("vendor")
            row.model = item.get("model")
            row.sys_object_id = item.get("sys_object_id")
            row.credential_profile_id = item.get("credential_profile_id")
    db.commit()


async def _writer_loop(session_id: int, queue: asyncio.Queue) -> None:
    db = SessionLocal()
    batch: list[dict] = []
    try:
        while True:
            item = await queue.get()
            try:
                if item is None or (isinstance(item, dict) and item.get("op") == "flush"):
                    _flush_writer(db, session_id, batch)
                    batch = []
                    if item is None:
                        return
                    continue
                batch.append(item)
                if len(batch) >= _WRITER_BATCH:
                    _flush_writer(db, session_id, batch)
                    batch = []
            except Exception:
                db.rollback()
                logger.error("scan writer failed session=%s", session_id)
                batch = []
            finally:
                queue.task_done()
    finally:
        db.close()


def _identity_payload(identity: SnmpIdentity) -> dict:
    return {
        "name": identity.sys_name,
        "location": identity.sys_location,
        "vendor": identity.vendor,
        "model": identity.model,
        "sys_object_id": identity.sys_object_id,
        "credential_profile_id": identity.profile_id,
    }


async def run_scan(session_id: int) -> None:
    global _current_task, _current_session_id
    snmp_engine: SnmpEngine | None = None
    queue: asyncio.Queue = asyncio.Queue()
    writer_task = asyncio.create_task(
        _writer_loop(session_id, queue),
        name=f"inform-scan-writer-{session_id}",
    )
    try:
        session = _load_session(session_id)
        if session is None:
            return
        parsed = parse_scan_target(session.target)
        hosts = [str(ip) for ip in parsed.hosts]
        profile_ids = _parse_profile_ids(session.profile_ids_json)
        profiles = _load_profiles(profile_ids)
        managed = _managed_ip_map()
        ping_timeout = int(session.ping_timeout_seconds or 1)
        ping_conc = int(session.ping_concurrency or 32)
        snmp_timeout = float(session.snmp_timeout_seconds or 2)
        snmp_conc = int(session.snmp_concurrency or 8)
        ping_sem = asyncio.Semaphore(ping_conc)
        snmp_sem = asyncio.Semaphore(snmp_conc)
        live_unmanaged: list[str] = []

        logger.info(
            "scan start user=%s session=%s target=%s hosts=%s profiles=%s "
            "ping_concurrency=%s snmp_concurrency=%s",
            session.started_by,
            session_id,
            session.target,
            session.total_hosts,
            [p.name for p in profiles],
            ping_conc,
            snmp_conc,
        )

        snmp_engine = SnmpEngine()

        async def ping_worker(ip: str) -> None:
            try:
                ok, rtt = await ping_one(ip, ping_timeout, ping_sem)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.debug("ping failed ip=%s", ip)
                ok, rtt = False, None
            already = ip in managed
            if ok and not already:
                live_unmanaged.append(ip)
            await queue.put(
                {
                    "op": "ping",
                    "ip": ip,
                    "ping_ok": ok,
                    "ping_rtt_ms": rtt,
                    "already_managed": already,
                    "managed_device_id": managed.get(ip),
                    "insert": already or ok,
                    "snmp_status": "skipped" if already else "no_snmp",
                }
            )

        await _run_batches(hosts, ping_conc, ping_worker, session_id)
        await queue.put({"op": "flush"})
        await queue.join()

        if not _should_stop(session_id) and profiles and live_unmanaged:

            async def snmp_worker(ip: str) -> None:
                try:
                    async with snmp_sem:
                        identity, err, _ = await identify(
                            snmp_engine,
                            ip,
                            profiles,
                            snmp_timeout,
                            retries=0,
                        )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.debug("snmp identify failed ip=%s", ip)
                    identity, err = None, SnmpErrorKind.OTHER
                payload: dict[str, Any] = {
                    "op": "snmp",
                    "ip": ip,
                    "snmp_status": "ok" if identity is not None else _snmp_status_from_error(err),
                }
                if identity is not None:
                    payload.update(_identity_payload(identity))
                    logger.debug("SNMP %s profile %s: ok", ip, identity.profile_id)
                else:
                    logger.debug(
                        "SNMP %s: %s",
                        ip,
                        err.value if err is not None else "no_snmp",
                    )
                await queue.put(payload)

            await _run_batches(live_unmanaged, snmp_conc, snmp_worker, session_id)
            await queue.join()
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        _mark_session_failed_if_unfinished(session_id, type(exc).__name__)
        raise
    finally:
        try:
            await queue.put(None)
            await writer_task
        except Exception:
            logger.debug("scan writer shutdown failed", exc_info=True)
        _finalize_session(session_id)
        if snmp_engine is not None:
            try:
                snmp_engine.close_dispatcher()
            except Exception:
                logger.debug("close_dispatcher failed", exc_info=True)
        current = asyncio.current_task()
        if _current_task is current:
            _current_task = None
            if _current_session_id == session_id:
                _current_session_id = None


async def probe_hosts(
    hosts: Sequence[str],
    profiles: Sequence[CredentialProfile],
    *,
    ping_timeout: int,
    ping_concurrency: int,
    snmp_timeout: int | float,
    snmp_concurrency: int,
    managed: dict[str, int],
) -> list[dict]:
    """Ping-then-SNMP probe used by CLI discover. Does not write scan tables."""
    ping_timeout, ping_conc, snmp_timeout_i, snmp_conc = clamp_scan_options(
        ping_timeout, ping_concurrency, int(snmp_timeout), snmp_concurrency
    )
    snmp_timeout_f = float(snmp_timeout_i)
    ping_sem = asyncio.Semaphore(ping_conc)
    snmp_sem = asyncio.Semaphore(snmp_conc)
    results: dict[str, dict] = {}
    live_unmanaged: list[str] = []

    async def ping_worker(ip: str) -> None:
        try:
            ok, rtt = await ping_one(ip, ping_timeout, ping_sem)
        except asyncio.CancelledError:
            raise
        except Exception:
            ok, rtt = False, None
        already = ip in managed
        if not already and not ok:
            return
        results[ip] = {
            "ip": ip,
            "ping_ok": ok,
            "ping_rtt_ms": rtt,
            "already_managed": already,
            "snmp_status": "skipped" if already else "no_snmp",
            "name": None,
            "location": None,
            "vendor": None,
            "model": None,
            "sys_object_id": None,
            "credential_profile_id": None,
        }
        if ok and not already:
            live_unmanaged.append(ip)

    await _run_batches(list(hosts), ping_conc, ping_worker, session_id=None)

    if profiles and live_unmanaged:
        snmp_engine = SnmpEngine()
        try:

            async def snmp_worker(ip: str) -> None:
                row = results.get(ip)
                if row is None:
                    return
                try:
                    async with snmp_sem:
                        identity, err, _ = await identify(
                            snmp_engine,
                            ip,
                            profiles,
                            snmp_timeout_f,
                            retries=0,
                        )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    identity, err = None, SnmpErrorKind.OTHER
                if identity is not None:
                    row["snmp_status"] = "ok"
                    row.update(_identity_payload(identity))
                else:
                    row["snmp_status"] = _snmp_status_from_error(err)

            await _run_batches(live_unmanaged, snmp_conc, snmp_worker, session_id=None)
        finally:
            snmp_engine.close_dispatcher()

    return [results[ip] for ip in hosts if ip in results]
