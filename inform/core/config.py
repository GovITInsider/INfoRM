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


def load_settings() -> Settings:
    config_path = get_config_path()
    raw_config = {}

    if config_path.exists():
        with open(config_path, "r") as f:
            raw_config = yaml.safe_load(f) or {}
    else:
        print(f"Warning: Config file not found at {config_path}. Using defaults + .env")

    return Settings(**raw_config)


settings = load_settings()
