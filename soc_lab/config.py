"""Load and validate the detection configuration (thresholds live in JSON, not in code)."""

from __future__ import annotations

import copy
import json
from pathlib import Path

from .i18n import Msg

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "detection_rules.json"

# Parameters every rule must define, and whether they must be positive numbers.
REQUIRED_RULE_PARAMS = {
    "R001": ["window_minutes", "failure_threshold", "high_severity_threshold"],
    "R002": ["lookback_minutes", "min_failures", "critical_failure_threshold"],
    "R003": ["entity_fields", "min_attempts", "failure_rate_threshold", "high_failure_rate"],
    "R004": ["window_minutes", "min_distinct_accounts", "high_distinct_accounts"],
    "R005": ["lockout_success_window_minutes", "rapid_source_change_minutes", "baseline_learning_days"],
}
RATE_PARAMS = {"failure_rate_threshold", "high_failure_rate"}
NON_NEGATIVE_PARAMS = {"baseline_learning_days"}


class ConfigError(ValueError):
    """Raised when the detection configuration is missing or invalid."""


def load_config(path: str | Path | None = None) -> dict:
    """Read the JSON configuration file and validate it."""
    config_path = Path(path) if path else DEFAULT_CONFIG_PATH
    if not config_path.exists():
        raise ConfigError(Msg("config_error.not_found", path=str(config_path)))
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(Msg("config_error.invalid_json", detail=str(exc))) from exc
    validate_config(config)
    return config


def validate_config(config: dict) -> None:
    """Check that the structure and values make sense. Raises ConfigError otherwise."""
    if not isinstance(config, dict) or "rules" not in config or "environment" not in config:
        raise ConfigError(Msg("config_error.sections"))

    env = config["environment"]
    for key in ("internal_networks", "business_hours"):
        if key not in env:
            raise ConfigError(Msg("config_error.missing_environment", key=key))
    hours = env["business_hours"]
    if not (0 <= hours.get("start_hour", -1) < hours.get("end_hour", -1) <= 24):
        raise ConfigError(Msg("config_error.business_hours"))

    for rule_id, params in REQUIRED_RULE_PARAMS.items():
        rule = config["rules"].get(rule_id)
        if rule is None:
            raise ConfigError(Msg("config_error.missing_rule", rule=rule_id))
        for param in params:
            if param not in rule:
                raise ConfigError(Msg("config_error.missing_param", rule=rule_id, param=param))
            value = rule[param]
            if param == "entity_fields":
                if not value or not set(value) <= {"source_ip", "username"}:
                    raise ConfigError(Msg("config_error.entity_fields", rule=rule_id))
                continue
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ConfigError(Msg("config_error.not_number", rule=rule_id, param=param, value=repr(value)))
            if param in RATE_PARAMS and not 0 < value <= 1:
                raise ConfigError(Msg("config_error.rate_range", rule=rule_id, param=param, value=value))
            if param in NON_NEGATIVE_PARAMS:
                if value < 0:
                    raise ConfigError(Msg("config_error.negative", rule=rule_id, param=param, value=value))
            elif value <= 0:
                raise ConfigError(Msg("config_error.not_positive", rule=rule_id, param=param, value=value))

    # Optional: how alerts are grouped into cases (soc_lab/correlation.py).
    correlation = config.get("correlation", {})
    window = correlation.get("window_minutes", 0) if isinstance(correlation, dict) else None
    if isinstance(window, bool) or not isinstance(window, (int, float)) or window < 0:
        raise ConfigError(Msg("config_error.correlation", value=repr(window)))


def with_overrides(config: dict, overrides: dict[str, dict]) -> dict:
    """Return a validated copy of `config` with selected rule parameters replaced.

    Example: with_overrides(cfg, {"R001": {"failure_threshold": 8}})
    """
    updated = copy.deepcopy(config)
    for rule_id, params in overrides.items():
        updated["rules"].setdefault(rule_id, {}).update(params)
    validate_config(updated)
    return updated
