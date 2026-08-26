import asyncio

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from inform.core.database import Base
from inform.core.models import CredentialProfile, Device, ScanResult, ScanSession
from inform.snmp.client import SnmpErrorKind, SnmpIdentity
from inform.snmp import scan as scan_mod
from inform.snmp.scan import (
    DiscoveryDisabledError,
    PublicSpaceError,
    ScanAlreadyRunning,
    UnsavedReviewError,
    begin_scan,
    cancel_current_scan,
    clamp_scan_options,
    fail_interrupted_sessions,
    probe_hosts,
    request_cancel,
    run_scan,
    start_scan_task,
)


def _attach_sqlite_hooks(eng):
    @event.listens_for(eng, "connect")
    def _connect(dbapi_connection, connection_record):
        dbapi_connection.isolation_level = None
        cur = dbapi_connection.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=30000")
        cur.close()

    @event.listens_for(eng, "begin")
    def _begin(conn):
        conn.exec_driver_sql("BEGIN IMMEDIATE")


@pytest.fixture
def scan_db(tmp_path, monkeypatch):
    db_path = tmp_path / "inform.db"
    eng = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False, "timeout": 30},
    )
    _attach_sqlite_hooks(eng)
    Base.metadata.create_all(bind=eng)
    Session = sessionmaker(autocommit=False, autoflush=False, bind=eng)

    monkeypatch.setattr(scan_mod, "engine", eng)
    monkeypatch.setattr(scan_mod, "SessionLocal", Session)
    monkeypatch.setattr("inform.core.database.engine", eng)
    monkeypatch.setattr("inform.core.database.SessionLocal", Session)
    monkeypatch.setattr(scan_mod.settings.discovery, "enabled", True)
    scan_mod._current_task = None
    scan_mod._current_session_id = None

    yield Session

    scan_mod._current_task = None
    scan_mod._current_session_id = None
    eng.dispose()


def _add_device(Session, ip: str, name: str = "sw") -> int:
    db = Session()
    try:
        device = Device(
            ip_address=ip,
            name=name,
            building="HQ",
            monitored=True,
            status="unknown",
        )
        db.add(device)
        db.commit()
        db.refresh(device)
        return device.id
    finally:
        db.close()


def _add_profile(Session, name: str = "campus") -> int:
    db = Session()
    try:
        profile = CredentialProfile(
            name=name,
            snmp_version="v2c",
            security_level="",
            community="public",
            username="",
            auth_protocol="",
            auth_key="",
            priv_protocol="",
            priv_key="",
        )
        db.add(profile)
        db.commit()
        db.refresh(profile)
        return profile.id
    finally:
        db.close()


def _session(Session, sid: int) -> ScanSession:
    db = Session()
    try:
        row = db.query(ScanSession).filter(ScanSession.id == sid).first()
        db.expunge(row)
        return row
    finally:
        db.close()


def _results(Session, sid: int) -> list[ScanResult]:
    db = Session()
    try:
        rows = (
            db.query(ScanResult)
            .filter(ScanResult.session_id == sid)
            .order_by(ScanResult.ip_address)
            .all()
        )
        for row in rows:
            db.expunge(row)
        return rows
    finally:
        db.close()


def _ping_map(live: dict[str, float | None]):
    async def fake_ping(ip, timeout_s, sem):
        if ip in live:
            return True, live[ip]
        return False, None

    return fake_ping


def test_clamp_scan_options_caps():
    ping_t, ping_c, snmp_t, snmp_c = clamp_scan_options(10, 999, 30, 100)
    assert ping_t == 3
    assert ping_c == 64
    assert snmp_t == 5
    assert snmp_c == 16


def test_clamp_scan_options_defaults():
    ping_t, ping_c, snmp_t, snmp_c = clamp_scan_options()
    assert ping_t == 1
    assert ping_c == 32
    assert snmp_t == 2
    assert snmp_c == 8


def test_clamp_hard_caps_override_settings(monkeypatch):
    monkeypatch.setattr(scan_mod.settings.discovery, "max_ping_concurrency", 256)
    monkeypatch.setattr(scan_mod.settings.discovery, "max_snmp_concurrency", 64)
    _, ping_c, _, snmp_c = clamp_scan_options(1, 256, 2, 64)
    assert ping_c == 64
    assert snmp_c == 16


def test_begin_scan_rejects_public_without_confirm(scan_db):
    with pytest.raises(PublicSpaceError):
        begin_scan("8.8.8.8")
    sid = begin_scan("8.8.8.8", confirm_public=True)
    assert sid >= 1
    row = _session(scan_db, sid)
    assert row.status == "running"
    assert row.total_hosts == 1


def test_begin_scan_clamps_concurrency(scan_db):
    sid = begin_scan(
        "10.50.12.10",
        ping_timeout_seconds=9,
        ping_concurrency=999,
        snmp_timeout_seconds=9,
        snmp_concurrency=999,
    )
    row = _session(scan_db, sid)
    assert row.ping_timeout_seconds == 3
    assert row.ping_concurrency == 64
    assert row.snmp_timeout_seconds == 5
    assert row.snmp_concurrency == 16


def test_begin_scan_one_scan_lock(scan_db):
    sid = begin_scan("10.50.12.10")
    with pytest.raises(ScanAlreadyRunning) as exc:
        begin_scan("10.50.12.11", discard_previous=True)
    assert exc.value.session_id == sid
    assert scan_db().query(ScanSession).count() == 1


def test_begin_scan_requires_discard_for_unsaved(scan_db):
    sid = begin_scan("10.50.12.10")
    db = scan_db()
    try:
        row = db.query(ScanSession).filter(ScanSession.id == sid).one()
        row.status = "completed"
        db.add(
            ScanResult(
                session_id=sid,
                ip_address="10.50.12.10",
                already_managed=False,
                ping_ok=True,
                snmp_status="no_snmp",
            )
        )
        db.commit()
    finally:
        db.close()

    with pytest.raises(UnsavedReviewError):
        begin_scan("10.50.12.11")

    sid2 = begin_scan("10.50.12.11", discard_previous=True)
    db = scan_db()
    try:
        sessions = db.query(ScanSession).all()
        assert len(sessions) == 1
        assert sessions[0].id == sid2
        assert db.query(ScanResult).count() == 0
    finally:
        db.close()


def test_fail_interrupted_sessions(scan_db):
    sid = begin_scan("10.50.12.10")
    fail_interrupted_sessions("interrupted by process restart")
    row = _session(scan_db, sid)
    assert row.status == "failed"
    assert row.error_message == "interrupted by process restart"
    assert row.finished_at is not None


def test_request_cancel_orphaned(scan_db):
    sid = begin_scan("10.50.12.10")
    request_cancel(sid)
    row = _session(scan_db, sid)
    assert row.status == "failed"
    assert row.error_message == "orphaned; no in-process task"


def test_discovery_disabled(scan_db, monkeypatch):
    monkeypatch.setattr(scan_mod.settings.discovery, "enabled", False)
    with pytest.raises(DiscoveryDisabledError):
        begin_scan("10.50.12.10")


def test_run_scan_drops_unmanaged_dead_keeps_managed_down(scan_db, monkeypatch):
    managed_id = _add_device(scan_db, "10.50.12.2", "core")
    monkeypatch.setattr(
        scan_mod,
        "ping_one",
        _ping_map({"10.50.12.1": 1.5}),
    )

    async def no_identify(*args, **kwargs):
        raise AssertionError("identify should not run without profiles")

    monkeypatch.setattr(scan_mod, "identify", no_identify)

    sid = begin_scan("10.50.12.0/30")

    async def _run():
        await run_scan(sid)

    asyncio.run(_run())

    row = _session(scan_db, sid)
    assert row.status == "completed"
    assert row.pinged_count == 2
    assert row.live_count == 1
    results = {r.ip_address: r for r in _results(scan_db, sid)}
    assert set(results) == {"10.50.12.1", "10.50.12.2"}
    assert results["10.50.12.1"].already_managed is False
    assert results["10.50.12.1"].ping_ok is True
    assert results["10.50.12.1"].snmp_status == "no_snmp"
    assert results["10.50.12.2"].already_managed is True
    assert results["10.50.12.2"].managed_device_id == managed_id
    assert results["10.50.12.2"].ping_ok is False
    assert results["10.50.12.2"].snmp_status == "skipped"


def test_run_scan_zero_profiles_live_hosts_no_snmp(scan_db, monkeypatch):
    monkeypatch.setattr(
        scan_mod,
        "ping_one",
        _ping_map({"10.50.12.10": 0.8}),
    )
    sid = begin_scan("10.50.12.10")
    asyncio.run(run_scan(sid))
    results = _results(scan_db, sid)
    assert len(results) == 1
    assert results[0].snmp_status == "no_snmp"
    assert results[0].already_managed is False
    assert results[0].ping_ok is True


def test_run_scan_skips_snmp_for_managed_live(scan_db, monkeypatch):
    _add_device(scan_db, "10.50.12.10")
    pid = _add_profile(scan_db)
    called: list[str] = []

    monkeypatch.setattr(
        scan_mod,
        "ping_one",
        _ping_map({"10.50.12.10": 2.0}),
    )

    async def fake_identify(engine, ip, profiles, timeout, retries=0):
        called.append(ip)
        return None, SnmpErrorKind.TIMEOUT, None

    monkeypatch.setattr(scan_mod, "identify", fake_identify)

    sid = begin_scan("10.50.12.10", profile_ids=[pid])
    asyncio.run(run_scan(sid))
    assert called == []
    result = _results(scan_db, sid)[0]
    assert result.already_managed is True
    assert result.snmp_status == "skipped"
    assert result.ping_ok is True


def test_run_scan_snmp_ok_and_auth_fail(scan_db, monkeypatch):
    pid = _add_profile(scan_db)
    monkeypatch.setattr(
        scan_mod,
        "ping_one",
        _ping_map({"10.50.12.1": 1.0, "10.50.12.2": 1.1}),
    )

    async def fake_identify(engine, ip, profiles, timeout, retries=0):
        if ip == "10.50.12.1":
            ident = SnmpIdentity(
                sys_name="sw1",
                sys_location="idf",
                sys_object_id="1.3.6.1.4.1.9.1.1",
                vendor="Cisco",
                model="C9300-48P",
                profile_id=profiles[0].id,
            )
            return ident, None, profiles[0].id
        return None, SnmpErrorKind.AUTH, None

    monkeypatch.setattr(scan_mod, "identify", fake_identify)

    sid = begin_scan("10.50.12.0/30", profile_ids=[pid])
    asyncio.run(run_scan(sid))
    results = {r.ip_address: r for r in _results(scan_db, sid)}
    assert results["10.50.12.1"].snmp_status == "ok"
    assert results["10.50.12.1"].name == "sw1"
    assert results["10.50.12.1"].vendor == "Cisco"
    assert results["10.50.12.1"].model == "C9300-48P"
    assert results["10.50.12.1"].credential_profile_id == pid
    assert results["10.50.12.2"].snmp_status == "auth_fail"
    row = _session(scan_db, sid)
    assert row.status == "completed"
    assert row.snmp_done_count == 2


def test_finalize_timeout_wins_over_cancel(scan_db):
    sid = begin_scan("10.50.12.10")
    db = scan_db()
    try:
        row = db.query(ScanSession).filter(ScanSession.id == sid).one()
        row.cancel_requested = True
        row.timeout_requested = True
        db.commit()
    finally:
        db.close()
    scan_mod._finalize_session(sid)
    row = _session(scan_db, sid)
    assert row.status == "failed"
    assert row.error_message == "timed out"


def test_finalize_cancel_flag(scan_db):
    sid = begin_scan("10.50.12.10")
    db = scan_db()
    try:
        row = db.query(ScanSession).filter(ScanSession.id == sid).one()
        row.cancel_requested = True
        db.commit()
    finally:
        db.close()
    scan_mod._finalize_session(sid)
    row = _session(scan_db, sid)
    assert row.status == "cancelled"
    assert row.error_message is None


def test_run_scan_cancel_requested(scan_db, monkeypatch):
    started = asyncio.Event()

    async def slow_ping(ip, timeout_s, sem):
        started.set()
        await asyncio.sleep(0.4)
        return True, 1.0

    monkeypatch.setattr(scan_mod, "ping_one", slow_ping)
    sid = begin_scan("10.50.12.10")

    async def _run():
        start_scan_task(sid)
        await started.wait()
        request_cancel(sid)
        task = scan_mod._current_task
        if task is not None:
            try:
                await task
            except asyncio.CancelledError:
                pass

    asyncio.run(_run())
    row = _session(scan_db, sid)
    assert row.status == "cancelled"


def test_watchdog_sets_timed_out(scan_db, monkeypatch):
    started = asyncio.Event()

    async def slow_ping(ip, timeout_s, sem):
        started.set()
        await asyncio.sleep(0.5)
        return True, 1.0

    monkeypatch.setattr(scan_mod, "ping_one", slow_ping)
    monkeypatch.setattr(scan_mod, "_watchdog_limit_seconds", lambda session: 0.05)
    sid = begin_scan("10.50.12.10")

    async def _run():
        start_scan_task(sid)
        await started.wait()
        task = scan_mod._current_task
        if task is not None:
            try:
                await task
            except asyncio.CancelledError:
                pass

    asyncio.run(_run())
    row = _session(scan_db, sid)
    assert row.status == "failed"
    assert row.error_message == "timed out"
    assert row.timeout_requested is True


def test_run_scan_crash_message_is_type_name(scan_db, monkeypatch):
    async def boom(ip, timeout_s, sem):
        raise RuntimeError("community=secret")

    monkeypatch.setattr(scan_mod, "ping_one", boom)
    # _run_batches swallows worker exceptions; force a scan-level crash
    async def exploding_batches(*args, **kwargs):
        raise RuntimeError("community=secret")

    monkeypatch.setattr(scan_mod, "_run_batches", exploding_batches)
    sid = begin_scan("10.50.12.10")
    with pytest.raises(RuntimeError):
        asyncio.run(run_scan(sid))
    row = _session(scan_db, sid)
    assert row.status == "failed"
    assert row.error_message == "RuntimeError"
    assert "secret" not in (row.error_message or "")


def test_probe_hosts_does_not_write_sessions(scan_db, monkeypatch):
    monkeypatch.setattr(
        scan_mod,
        "ping_one",
        _ping_map({"10.50.12.10": 1.0}),
    )

    async def _run():
        return await probe_hosts(
            ["10.50.12.10", "10.50.12.11"],
            [],
            ping_timeout=1,
            ping_concurrency=8,
            snmp_timeout=2,
            snmp_concurrency=4,
            managed={},
        )

    rows = asyncio.run(_run())
    assert [r["ip"] for r in rows] == ["10.50.12.10"]
    assert rows[0]["snmp_status"] == "no_snmp"
    db = scan_db()
    try:
        assert db.query(ScanSession).count() == 0
        assert db.query(ScanResult).count() == 0
    finally:
        db.close()


def test_writer_flush_error_does_not_hang(scan_db, monkeypatch):
    monkeypatch.setattr(
        scan_mod,
        "ping_one",
        _ping_map({"10.50.12.10": 1.0}),
    )

    def boom(*args, **kwargs):
        raise RuntimeError("sqlite busy")

    monkeypatch.setattr(scan_mod, "_flush_writer", boom)
    sid = begin_scan("10.50.12.10")
    asyncio.run(asyncio.wait_for(run_scan(sid), timeout=2))
    row = _session(scan_db, sid)
    assert row.status == "failed"
    assert row.error_message == "scan writer failed"


def test_run_batches_survives_second_cancel():
    started = asyncio.Event()
    finished = asyncio.Event()

    async def slow_worker(_item):
        started.set()
        await asyncio.sleep(0.2)
        finished.set()

    async def _run():
        task = asyncio.create_task(
            scan_mod._run_batches(["x"], 1, slow_worker, session_id=None)
        )
        await started.wait()
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        assert finished.is_set()

    asyncio.run(_run())


def test_cancel_current_scan_sets_cancelled(scan_db, monkeypatch):
    started = asyncio.Event()

    async def slow_ping(ip, timeout_s, sem):
        started.set()
        await asyncio.sleep(0.4)
        return True, 1.0

    monkeypatch.setattr(scan_mod, "ping_one", slow_ping)
    sid = begin_scan("10.50.12.10")

    async def _run():
        start_scan_task(sid)
        await started.wait()
        await cancel_current_scan()

    asyncio.run(_run())
    row = _session(scan_db, sid)
    assert row.status == "cancelled"
