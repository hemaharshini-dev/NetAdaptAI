"""Canonical control names shared by parsers, rules, the API, and training."""

from __future__ import annotations

from typing import Any

BENCHMARK = "CIS Cisco IOS XE 17.x Benchmark"
BENCHMARK_VERSION = "2.2.1"

# A deliberately small mapping vocabulary for the prototype's cross-vendor and
# human-learning demonstrations. The remaining Cisco benchmark controls use
# stable canonical names derived from their existing normalized model fields.
CANONICAL_TO_FIELD = {
    "management.ssh.version": "ssh_version",
    "management.telnet.enabled": "telnet_enabled",
    "management.http.enabled": "http_enabled",
    "logging.enabled": "logging_enabled",
    "logging.remote_logging.enabled": "logging_host",
    "management.admin_timeout_minutes": "admin_timeout_minutes",
}
FIELD_TO_CANONICAL = {value: key for key, value in CANONICAL_TO_FIELD.items()}
_SUPPORTED_FIELDS = set(CANONICAL_TO_FIELD.values())


def register_supported_fields(fields) -> None:
    """Register the normalized model fields that benchmark rules can evaluate."""
    _SUPPORTED_FIELDS.update(fields)


def canonical_control_for_field(field: str) -> str:
    if field in FIELD_TO_CANONICAL:
        return FIELD_TO_CANONICAL[field]
    if field.startswith("aaa_"):
        return f"authentication.aaa.{field.removeprefix('aaa_')}"
    if field.startswith("banner_"):
        return f"banners.{field.removeprefix('banner_')}"
    if field.startswith("snmp_"):
        return f"snmp.{field.removeprefix('snmp_')}"
    if field.startswith("ntp_"):
        return f"ntp.{field.removeprefix('ntp_')}"
    if field.startswith("logging_"):
        return f"logging.{field.removeprefix('logging_')}"
    if field.startswith("no_service_"):
        return f"services.{field.removeprefix('no_service_')}.disabled"
    if field.startswith("service_tcp_"):
        return f"services.{field.removeprefix('service_')}.enabled"
    if field.startswith("vty_") or field.startswith("aux_") or field.startswith("con_"):
        return f"management.access.{field}"
    return f"security.{field}"


def field_for_canonical_control(control: str) -> str | None:
    if control in CANONICAL_TO_FIELD:
        return CANONICAL_TO_FIELD[control]
    # Rule-derived controls are explicitly namespaced and use the existing
    # normalized field suffix. This keeps the current rule set intact while
    # making their canonical mapping visible in the rule and API models.
    prefix = "security."
    if control.startswith(prefix):
        field = control[len(prefix):]
        return field if field in _SUPPORTED_FIELDS else None
    if control.startswith("authentication.aaa."):
        field = "aaa_" + control.removeprefix("authentication.aaa.")
        return field if field in _SUPPORTED_FIELDS else None
    if control.startswith("banners."):
        field = "banner_" + control.removeprefix("banners.")
        return field if field in _SUPPORTED_FIELDS else None
    if control.startswith("snmp."):
        field = "snmp_" + control.removeprefix("snmp.")
        return field if field in _SUPPORTED_FIELDS else None
    if control.startswith("ntp."):
        field = "ntp_" + control.removeprefix("ntp.")
        return field if field in _SUPPORTED_FIELDS else None
    if control.startswith("logging."):
        field = "logging_" + control.removeprefix("logging.")
        return field if field in _SUPPORTED_FIELDS else None
    if control.startswith("management.access."):
        field = control.removeprefix("management.access.")
        return field if field in _SUPPORTED_FIELDS else None
    if control.startswith("services."):
        suffix = control.removeprefix("services.")
        if suffix.endswith(".disabled"):
            field = "no_service_" + suffix.removesuffix(".disabled")
            return field if field in _SUPPORTED_FIELDS else None
        if suffix.endswith(".enabled"):
            field = "service_" + suffix.removesuffix(".enabled")
            return field if field in _SUPPORTED_FIELDS else None
        field = f"service_{suffix}"
        return field if field in _SUPPORTED_FIELDS else None
    return None


def coerce_canonical_value(control: str, value: Any) -> Any:
    """Validate and coerce a human/LLM proposal to the target model field."""
    field = field_for_canonical_control(control)
    if field is None:
        raise ValueError(f"Unsupported canonical control: {control}")
    if field == "ssh_version":
        if str(value).strip() not in {"1", "2"}:
            raise ValueError("SSH version must be 1 or 2")
        return str(value).strip()
    if field == "admin_timeout_minutes":
        timeout = int(value)
        if timeout < 0:
            raise ValueError("Timeout must be non-negative")
        return timeout
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in {"true", "enabled", "yes", "on", "1"}:
        return True
    if normalized in {"false", "disabled", "no", "off", "0"}:
        return False
    raise ValueError(f"{control} expects a boolean or an explicit enabled/disabled value")

