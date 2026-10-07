"""Account cap, account-manager flag, and the management pages for issue #10."""

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from typer.testing import CliRunner

from inform.core.accounts import (
    AccountError,
    change_own_password,
    create_account,
    remove_account,
    reset_password,
    set_account_manager,
    validate_new_username,
    validate_password,
)
from inform.core.auth import hash_password, verify_password
from inform.core.database import Base
from inform.core.models import User

import pytest

ADA = "password-ada"
BEA = "password-bea"
_HASHES = {}


def _hash(password):
    if password not in _HASHES:
        _HASHES[password] = hash_password(password)
    return _HASHES[password]


def _engine(tmp_path):
    return create_engine(
        f"sqlite:///{tmp_path / 'inform.db'}",
        connect_args={"check_same_thread": False, "timeout": 30},
    )


def _session_factory(eng):
    Base.metadata.create_all(bind=eng)
    return sessionmaker(autocommit=False, autoflush=False, bind=eng)


def _add(db, username, *, manager, password="hash-not-used"):
    user = User(
        username=username,
        hashed_password=password if password != "hash-not-used" else "x" * 16,
        is_account_manager=manager,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def db(tmp_path):
    eng = _engine(tmp_path)
    Session = _session_factory(eng)
    session = Session()
    try:
        yield session
    finally:
        session.close()
        eng.dispose()


def test_new_username_rules():
    assert validate_new_username(" Ada ") == "ada"
    assert validate_new_username("ab") == "ab"
    assert validate_new_username("a" * 32) == "a" * 32
    assert validate_new_username("ops_1.desk") == "ops_1.desk"
    for bad in ("a", "a" * 33, "1ada", "ada b", "Ada!", "", " "):
        with pytest.raises(AccountError, match="2 to 32"):
            validate_new_username(bad)


def test_password_rules():
    assert validate_password("12345678") == "12345678"
    assert validate_password("p" * 200) == "p" * 200
    for bad in ("1234567", "p" * 201, "password\n", None, ""):
        with pytest.raises(AccountError, match="8 to 200"):
            validate_password(bad)


def test_create_stores_lowercase_and_flag(db):
    manager = create_account(db, "Ada", ADA, account_manager=True)
    assert manager.username == "ada"
    assert manager.is_account_manager is True
    normal = create_account(db, "Bea", BEA, account_manager=False, actor=manager)
    assert normal.username == "bea"
    assert normal.is_account_manager is False


def test_normal_actor_cannot_create_or_reset(db):
    manager = _add(db, "ada", manager=True)
    normal = _add(db, "bea", manager=False)
    with pytest.raises(AccountError, match="account manager"):
        create_account(db, "cam", ADA, account_manager=False, actor=normal)
    with pytest.raises(AccountError, match="account manager"):
        reset_password(db, normal, manager.id, ADA)
    with pytest.raises(AccountError, match="account manager"):
        remove_account(db, normal, manager.id)
    with pytest.raises(AccountError, match="account manager"):
        create_account(db, "cam", ADA, account_manager=False, actor=None)


def test_cap_is_ten(db):
    manager = _add(db, "ada", manager=True)
    for i in range(9):
        _add(db, f"user{i}", manager=False)
    with pytest.raises(AccountError, match="10 accounts"):
        create_account(db, "extra", ADA, account_manager=False, actor=manager)
    assert db.query(User).count() == 10


def test_cannot_remove_self_or_last_manager(db):
    manager = _add(db, "ada", manager=True)
    other = _add(db, "bea", manager=True)
    with pytest.raises(AccountError, match="signed in as"):
        remove_account(db, manager, manager.id)
    remove_account(db, manager, other.id)
    assert db.query(User).count() == 1
    with pytest.raises(AccountError, match="At least one"):
        set_account_manager(db, manager, manager.id, False)
    assert db.query(User).filter(User.id == manager.id).one().is_account_manager is True


def test_second_manager_can_remove_the_first(db):
    first = _add(db, "ada", manager=True)
    second = _add(db, "bea", manager=False)
    set_account_manager(db, first, second.id, True)
    remove_account(db, second, first.id)
    left = db.query(User).one()
    assert left.username == "bea"
    assert left.is_account_manager is True


def test_change_own_password_checks_current(db):
    user = _add(db, "bea", manager=False, password=_hash(BEA))
    before = user.hashed_password
    with pytest.raises(AccountError, match="do not match"):
        change_own_password(db, user, BEA, "password-new", "password-other")
    with pytest.raises(AccountError, match="does not match"):
        change_own_password(db, user, "wrong-password", "password-new", "password-new")
    db.refresh(user)
    assert user.hashed_password == before
    change_own_password(db, user, BEA, "password-new", "password-new")
    db.refresh(user)
    assert verify_password("password-new", user.hashed_password)
    assert not verify_password(BEA, user.hashed_password)


def test_reset_replaces_hash(db):
    manager = _add(db, "ada", manager=True)
    user = _add(db, "bea", manager=False, password=_hash(BEA))
    reset_password(db, manager, user.id, "password-new")
    db.refresh(user)
    assert verify_password("password-new", user.hashed_password)
    assert not verify_password(BEA, user.hashed_password)


def test_migration_promotes_existing_rows_only(tmp_path, monkeypatch):
    eng = _engine(tmp_path)
    Base.metadata.create_all(bind=eng)
    with eng.begin() as conn:
        conn.execute(text("DROP TABLE users"))
        conn.execute(text(
            "CREATE TABLE users ("
            "id INTEGER PRIMARY KEY, "
            "username VARCHAR(50) NOT NULL UNIQUE, "
            "hashed_password VARCHAR(128) NOT NULL, "
            "is_active BOOLEAN, "
            "created_at DATETIME)"
        ))
        conn.execute(text(
            "INSERT INTO users (username, hashed_password, is_active) "
            "VALUES ('Legacy', 'hash', 1)"
        ))
    monkeypatch.setattr("inform.core.database.engine", eng)
    from inform.core.database import migrate_schema

    migrate_schema()
    Session = sessionmaker(bind=eng)
    db = Session()
    legacy = db.query(User).filter(User.username == "Legacy").one()
    assert legacy.is_account_manager is True
    created = create_account(db, "Bea", BEA, account_manager=False, actor=legacy)
    assert created.is_account_manager is False
    migrate_schema()
    db.expire_all()
    assert db.query(User).filter(User.username == "Legacy").one().is_account_manager is True
    assert db.query(User).filter(User.username == "bea").one().is_account_manager is False
    db.close()
    eng.dispose()


def test_create_admin_cli(tmp_path, monkeypatch):
    eng = _engine(tmp_path)
    Session = _session_factory(eng)
    monkeypatch.setattr("inform.core.database.engine", eng)
    monkeypatch.setattr("inform.core.database.SessionLocal", Session)
    from inform.cli.main import app as cli

    monkeypatch.setattr("inform.cli.main.SessionLocal", Session)
    runner = CliRunner()

    ok = runner.invoke(cli, ["create-admin", "--username", "Ada", "--password", ADA])
    assert ok.exit_code == 0
    assert "ada" in ok.output

    short = runner.invoke(cli, ["create-admin", "--username", "bea", "--password", "short"])
    assert short.exit_code == 1
    assert "8 to 200" in short.output

    db = Session()
    try:
        rows = db.query(User).all()
        assert [row.username for row in rows] == ["ada"]
        assert rows[0].is_account_manager is True
    finally:
        db.close()
        eng.dispose()


@pytest.fixture
def client(tmp_path, monkeypatch):
    eng = _engine(tmp_path)
    Session = _session_factory(eng)
    monkeypatch.setattr("inform.core.database.engine", eng)
    monkeypatch.setattr("inform.core.database.SessionLocal", Session)
    monkeypatch.setattr("inform.core.auth.SessionLocal", Session)

    import web.main as web_main

    monkeypatch.setattr(web_main, "SessionLocal", Session)
    monkeypatch.setattr(web_main, "engine", eng)
    monkeypatch.setattr(web_main, "ensure_schema", lambda: None)
    monkeypatch.setattr(web_main, "fail_interrupted_sessions", lambda message: None)

    async def _no_cancel():
        return None

    monkeypatch.setattr(web_main, "cancel_current_scan", _no_cancel)

    db = Session()
    try:
        _add(db, "ada", manager=True, password=_hash(ADA))
        _add(db, "bea", manager=False, password=_hash(BEA))
        _add(db, "Ops.Lead", manager=False, password=_hash(ADA))
    finally:
        db.close()

    from fastapi.testclient import TestClient

    with TestClient(web_main.app) as test_client:
        yield test_client, Session
    eng.dispose()


def _login(client, username, password):
    response = client.post(
        "/manage/login",
        data={"username": username, "password": password},
        follow_redirects=False,
    )
    assert response.status_code == 302, response.text
    assert response.headers["location"].endswith("/manage")
    return response


def _token(client):
    return client.cookies.get("access_token")


def _use_token(client, token):
    client.cookies.clear()
    if token:
        client.cookies.set("access_token", token, path="/")


def test_manager_sees_users_and_normal_does_not(client):
    http, _Session = client
    _login(http, "ada", ADA)
    home = http.get("/manage")
    assert home.status_code == 200
    assert "Signed in as" in home.text
    assert 'href="/manage/users"' in home.text
    assert 'href="/manage/password"' in home.text
    users = http.get("/manage/users")
    assert users.status_code == 200
    assert "3 of 10" in users.text
    assert "Add an account" in users.text

    buildings = http.get("/manage/buildings")
    assert buildings.status_code == 200
    assert 'href="/manage/users"' in buildings.text
    profiles = http.get("/manage/profiles")
    assert profiles.status_code == 200
    assert 'href="/manage/users"' in profiles.text
    discover = http.get("/manage/discover", follow_redirects=True)
    assert discover.status_code == 200
    assert 'href="/manage/users"' in discover.text

    _login(http, "bea", BEA)
    home = http.get("/manage")
    assert 'href="/manage/users"' not in home.text
    assert 'href="/manage/password"' in home.text
    blocked = http.get("/manage/users", follow_redirects=False)
    assert blocked.status_code == 302
    assert "account+manager" in blocked.headers["location"]
    devices = http.get("/manage/devices")
    assert devices.status_code == 200
    exported = http.get("/manage/export")
    assert exported.status_code == 200


def test_normal_user_cannot_mutate_accounts(client):
    http, Session = client
    _login(http, "bea", BEA)
    db = Session()
    try:
        before = db.query(User).count()
    finally:
        db.close()
    created = http.post(
        "/manage/users",
        data={"username": "cam", "password": ADA},
        follow_redirects=False,
    )
    assert created.status_code == 302
    assert "/manage?" in created.headers["location"]
    removed = http.post("/manage/users/1/delete", follow_redirects=False)
    assert removed.status_code == 302
    reset = http.post(
        "/manage/users/1/password",
        data={"password": "password-new"},
        follow_redirects=False,
    )
    assert reset.status_code == 302
    flagged = http.post(
        "/manage/users/1/manager",
        data={"account_manager": "1"},
        follow_redirects=False,
    )
    assert flagged.status_code == 302
    db = Session()
    try:
        assert db.query(User).count() == before
        bea = db.query(User).filter(User.username == "bea").one()
        assert verify_password(BEA, bea.hashed_password)
        assert bea.is_account_manager is False
    finally:
        db.close()


def test_manager_adds_and_cannot_remove_self(client):
    http, Session = client
    _login(http, "ada", ADA)
    added = http.post(
        "/manage/users",
        data={"username": " Cam ", "password": ADA},
        follow_redirects=True,
    )
    assert added.status_code == 200
    assert "cam" in added.text
    assert "4 of 10" in added.text
    db = Session()
    try:
        ada_id = db.query(User).filter(User.username == "ada").one().id
    finally:
        db.close()
    refused = http.post(f"/manage/users/{ada_id}/delete", follow_redirects=True)
    assert "cannot remove the account you are signed in as" in refused.text
    db = Session()
    try:
        assert db.query(User).filter(User.username == "ada").count() == 1
    finally:
        db.close()


def test_own_password_keeps_session_and_reset_keeps_session(client):
    http, Session = client
    _login(http, "bea", BEA)
    changed = http.post(
        "/manage/password",
        data={
            "current_password": BEA,
            "new_password": "password-new",
            "confirm_password": "password-new",
        },
        follow_redirects=True,
    )
    assert "Password changed." in changed.text
    still = http.get("/manage/password")
    assert still.status_code == 200
    assert "bea" in still.text
    bea_token = _token(http)

    _use_token(http, None)
    _login(http, "bea", "password-new")
    _use_token(http, None)
    failed = http.post(
        "/manage/login",
        data={"username": "bea", "password": BEA},
    )
    assert "Invalid username or password" in failed.text

    _login(http, "ada", ADA)
    db = Session()
    try:
        bea_id = db.query(User).filter(User.username == "bea").one().id
    finally:
        db.close()
    http.post(
        f"/manage/users/{bea_id}/password",
        data={"password": "password-reset"},
        follow_redirects=False,
    )
    _use_token(http, bea_token)
    assert http.get("/manage").status_code == 200
    _use_token(http, None)
    _login(http, "bea", "password-reset")


def test_removed_account_loses_access_on_next_request(client):
    http, Session = client
    _login(http, "bea", BEA)
    bea_token = _token(http)
    _login(http, "ada", ADA)
    db = Session()
    try:
        bea_id = db.query(User).filter(User.username == "bea").one().id
    finally:
        db.close()
    gone = http.post(f"/manage/users/{bea_id}/delete", follow_redirects=True)
    assert "Account removed." in gone.text
    _use_token(http, bea_token)
    denied = http.get("/manage/devices", follow_redirects=False)
    assert denied.status_code == 302
    assert denied.headers["location"].endswith("/manage/login")


def test_legacy_username_still_logs_in(client):
    http, _Session = client
    _login(http, "Ops.Lead", ADA)
    home = http.get("/manage")
    assert "Ops.Lead" in home.text
    _use_token(http, None)
    failed = http.post(
        "/manage/login",
        data={"username": "ops.lead", "password": ADA},
    )
    assert "Invalid username or password" in failed.text


def test_cannot_demote_last_account_manager(client):
    http, Session = client
    _login(http, "ada", ADA)
    db = Session()
    try:
        ada_id = db.query(User).filter(User.username == "ada").one().id
    finally:
        db.close()
    refused = http.post(
        f"/manage/users/{ada_id}/manager",
        data={"account_manager": "0"},
        follow_redirects=True,
    )
    assert "At least one account manager has to remain." in refused.text
    db = Session()
    try:
        assert db.query(User).filter(User.id == ada_id).one().is_account_manager is True
    finally:
        db.close()
