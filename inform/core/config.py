import sys
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


# Nested models. YAML for these sections is applied onto a constructed Settings
# object. BaseSettings() alone can keep the field defaults (30) and ignore the file.
_SECTIONS = (
    ("security", SecuritySettings),
    ("web", WebSettings),
    ("general", GeneralSettings),
    ("discovery", DiscoverySettings),
    ("logging", LoggingSettings),
    ("monitoring", MonitoringSettings),
)
_PLACEHOLDER_SECRETS = {"", "CHANGE_ME_IN_.env"}
_REFRESH_KEYS = ("auto_refresh_seconds", "noc_auto_refresh_seconds")


class _MergingLoader(yaml.SafeLoader):
    """YAML loader that merges duplicate mappings instead of keeping only the last one."""


def _construct_mapping(loader, node):
    loader.flatten_mapping(node)
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        value = loader.construct_object(value_node)
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            merged = dict(result[key])
            merged.update(value)
            result[key] = merged
        else:
            result[key] = value
    return result


_MergingLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def _search_section(node, section, depth=0):
    if not isinstance(node, dict) or depth > 8:
        return None
    for key, value in node.items():
        if key == section and isinstance(value, dict):
            return value
        found = _search_section(value, section, depth + 1)
        if found is not None:
            return found
    return None


def _search_scalar(node, key, depth=0):
    if not isinstance(node, dict) or depth > 8:
        return None
    if key in node and not isinstance(node[key], (dict, list)):
        return node[key]
    for value in node.values():
        found = _search_scalar(value, key, depth + 1)
        if found is not None:
            return found
    return None


def _section_dict(raw, name):
    direct = raw.get(name) if isinstance(raw, dict) else None
    if isinstance(direct, dict):
        return dict(direct)
    found = _search_section(raw, name)
    if isinstance(found, dict):
        return dict(found)
    return {}


def load_settings() -> Settings:
    config_path = get_config_path()
    raw_config = {}

    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as handle:
            raw_config = yaml.load(handle, Loader=_MergingLoader) or {}
    else:
        print(f"Warning: Config file not found at {config_path}. Using defaults + .env")

    if not isinstance(raw_config, dict):
        raise ValueError(f"{config_path} must contain a mapping")

    # Environment and defaults first. Copy each config.yaml section on top,
    # then store the result with model_construct so a later read cannot fall
    # back to the field default.
    env_settings = Settings()
    built = {}
    for name, model_cls in _SECTIONS:
        incoming = _section_dict(raw_config, name)
        if name == "security":
            secret = incoming.get("secret_key")
            if secret in _PLACEHOLDER_SECRETS:
                incoming.pop("secret_key", None)
        if name == "web":
            top_web = raw_config.get("web")
            top_web = top_web if isinstance(top_web, dict) else {}
            for key in _REFRESH_KEYS:
                if key in incoming or key in top_web:
                    continue
                found = _search_scalar(raw_config, key)
                if found is not None:
                    incoming[key] = found
                    print(
                        f"Warning: {key} is not under the top-level web: section "
                        f"in {config_path}; using {found}",
                        file=sys.stderr,
                    )
        current = getattr(env_settings, name).model_dump()
        current.update(incoming)
        built[name] = model_cls.model_validate(current)

    loaded = Settings.model_construct(**built)
    if config_path.exists() and loaded.web.auto_refresh_seconds == 30:
        text = config_path.read_text(encoding="utf-8", errors="replace")
        if "auto_refresh_seconds" in text:
            print(
                f"Warning: {config_path} mentions auto_refresh_seconds but the "
                f"loaded value is 30. Top-level keys: {list(raw_config)}. "
                f"web section: {raw_config.get('web')!r}",
                file=sys.stderr,
            )
    return loaded


settings = load_settings()
