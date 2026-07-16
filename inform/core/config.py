from pathlib import Path
import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional

# ========================
# Nested Settings
# ========================
class SecuritySettings(BaseModel):
    secret_key: str
    token_expires_minutes: int = 480

class WebSettings(BaseModel):
    auto_refresh_seconds: int = 30
    noc_auto_refresh_seconds: int = 30

class GeneralSettings(BaseModel):
    log_level: str = "INFO"

class DiscoverySettings(BaseModel):
    enabled: bool = True

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
