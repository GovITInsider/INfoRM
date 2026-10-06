from inform.core.config import load_settings


def test_yaml_refresh_overrides_defaults(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
general:
  log_level: INFO
  poll_interval_seconds: 20

monitoring:
  countbeforealarm: 2
  poll_interval_seconds: 20

web:
  auto_refresh_seconds: 20
  noc_auto_refresh_seconds: 20
  local_timezone: "America/Chicago"

security:
  secret_key: "CHANGE_ME_IN_.env"
  token_expires_minutes: 90
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("SECURITY__SECRET_KEY", "from-env")
    monkeypatch.setattr("inform.core.config.get_config_path", lambda: config_path)

    loaded = load_settings()

    assert loaded.web.auto_refresh_seconds == 20
    assert loaded.web.noc_auto_refresh_seconds == 20
    assert loaded.web.local_timezone == "America/Chicago"
    assert loaded.monitoring.poll_interval_seconds == 20
    assert loaded.monitoring.countbeforealarm == 2
    assert loaded.security.token_expires_minutes == 90
    assert loaded.security.secret_key == "from-env"


def test_refresh_is_found_when_web_is_indented_under_monitoring(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
monitoring:
  poll_interval_seconds: 20
  web:
    auto_refresh_seconds: 20
    noc_auto_refresh_seconds: 20
security:
  secret_key: "CHANGE_ME_IN_.env"
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("SECURITY__SECRET_KEY", "from-env")
    monkeypatch.setattr("inform.core.config.get_config_path", lambda: config_path)

    loaded = load_settings()

    assert loaded.web.auto_refresh_seconds == 20
    assert loaded.web.noc_auto_refresh_seconds == 20
    assert loaded.monitoring.poll_interval_seconds == 20


def test_duplicate_web_sections_are_merged(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
web:
  auto_refresh_seconds: 20
  noc_auto_refresh_seconds: 20
web:
  local_timezone: "America/Chicago"
security:
  secret_key: "CHANGE_ME_IN_.env"
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("SECURITY__SECRET_KEY", "from-env")
    monkeypatch.setattr("inform.core.config.get_config_path", lambda: config_path)

    loaded = load_settings()

    assert loaded.web.auto_refresh_seconds == 20
    assert loaded.web.noc_auto_refresh_seconds == 20
    assert loaded.web.local_timezone == "America/Chicago"


def test_yaml_secret_replaces_env_when_it_is_real(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
security:
  secret_key: "from-yaml"
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("SECURITY__SECRET_KEY", "from-env")
    monkeypatch.setattr("inform.core.config.get_config_path", lambda: config_path)

    loaded = load_settings()

    assert loaded.security.secret_key == "from-yaml"
