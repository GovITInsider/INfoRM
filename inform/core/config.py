from pathlib import Path
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# ========================
# Nested Settings
# ========================
class SecuritySettings(BaseModel):
    secret_key: str
    token_expires_minutes: int = 480

class ExternalLink(BaseModel):
    """One public navbar link. Stored in config.yaml so updates do not wipe it."""

    name: str
    url: str

    @field_validator("name")
    @classmethod
    def name_not_blank(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("external link name is empty")
        if len(cleaned) > 80:
            raise ValueError("external link name is longer than 80 characters")
        return cleaned

    @field_validator("url")
    @classmethod
    def http_url(cls, value: str) -> str:
        cleaned = value.strip()
        parsed = urlparse(cleaned)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("external link url must start with http:// or https://")
        return cleaned


class WebSettings(BaseModel):
    auto_refresh_seconds: int = 30
    noc_auto_refresh_seconds: int = 30
    local_timezone: str = "America/Los_Angeles"
    external_links: list[ExternalLink] = Field(default_factory=list)

class GeneralSettings(BaseModel):
    log_level: str = "INFO"

class DiscoverySettings(BaseModel):
    enabled: bool = True
    max_prefix_len: int = 24
    default_ping_timeout_seconds: int = 1
    default_ping_concurrency: int = 32
    default_snmp_timeout_seconds: int = 2
    default_snmp_concurrency: int = 8
    max_ping_concurrency: int = 64
    max_snmp_concurrency: int = 16
    scan_max_runtime_seconds: int = 900

class LoggingSettings(BaseModel):
    log_file: str = "logs/inform.log"

class MonitoringSettings(BaseModel):
    countbeforealarm: int = 3
    poll_interval_seconds: int = 30

# ========================
# Main Settings Class
# ========================
class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_nested_delimiter="__",      # Allows SECURITY__SECRET_KEY in .env
        extra="ignore"
    )

    security: SecuritySettings = Field(default_factory=SecuritySettings)
    web: WebSettings = Field(default_factory=WebSettings)
    general: GeneralSettings = Field(default_factory=GeneralSettings)
    discovery: DiscoverySettings = Field(default_factory=DiscoverySettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    monitoring: MonitoringSettings = Field(default_factory=MonitoringSettings)


def get_config_path() -> Path:
    return Path(__file__).parent.parent.parent / "config" / "config.yaml"


# Nested models. YAML for these sections is applied after Settings() is built.
_SECTIONS = (
    ("security", SecuritySettings),
    ("web", WebSettings),
    ("general", GeneralSettings),
    ("discovery", DiscoverySettings),
    ("logging", LoggingSettings),
    ("monitoring", MonitoringSettings),
)
_PLACEHOLDER_SECRETS = {"", "CHANGE_ME_IN_.env"}


def load_settings() -> Settings:
    config_path = get_config_path()
    raw_config = {}

    if config_path.exists():
        with open(config_path, "r") as f:
            raw_config = yaml.safe_load(f) or {}
    else:
        print(f"Warning: Config file not found at {config_path}. Using defaults + .env")

    if not isinstance(raw_config, dict):
        raise ValueError(f"{config_path} must contain a mapping")

    # Build from the environment and field defaults first, then copy each
    # config.yaml section on top. Passing the file into Settings() drops
    # nested values on some pydantic-settings builds, so a configured
    # auto_refresh_seconds of 20 still came back as the default 30.
    settings = Settings()
    for name, model_cls in _SECTIONS:
        incoming = raw_config.get(name)
        if not isinstance(incoming, dict):
            continue
        incoming = dict(incoming)
        if name == "security":
            secret = incoming.get("secret_key")
            if secret in _PLACEHOLDER_SECRETS:
                incoming.pop("secret_key", None)
        if not incoming:
            continue
        current = getattr(settings, name).model_dump()
        current.update(incoming)
        setattr(settings, name, model_cls.model_validate(current))
    return settings


settings = load_settings()
