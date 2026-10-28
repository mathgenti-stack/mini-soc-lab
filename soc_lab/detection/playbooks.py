"""Analyst guidance for each rule: benign explanations, false-positive notes and next steps.

Kept separate from the detection logic so guidance can be edited without touching rules.
The wording lives in the translation files (`soc_lab/locales/*.json`, keys `playbook.<rule>.<section>.<n>`),
so each playbook can be read in any supported language.
All recommended actions are for a junior analyst to propose or perform through the
organisation's normal processes - this tool never acts on real systems.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..i18n import Msg, keys_with_prefix

PLAYBOOK_KEYS = [
    "R001", "R002", "R003", "R004",
    "R005:lockout_then_success", "R005:off_hours_new_source", "R005:rapid_source_change",
]


@dataclass(frozen=True)
class Playbook:
    description: str
    benign_explanations: list[str]
    false_positive_considerations: list[str]
    investigation_steps: list[str]
    containment_actions: list[str]
    limitations: list[str]


def _items(prefix: str) -> list[Msg]:
    return [Msg(key) for key in keys_with_prefix(prefix)]


def _playbook(key: str) -> Playbook:
    prefix = f"playbook.{key}"
    return Playbook(
        description=Msg(f"{prefix}.description"),
        benign_explanations=_items(f"{prefix}.benign_explanations"),
        false_positive_considerations=_items(f"{prefix}.false_positive_considerations"),
        investigation_steps=_items(f"{prefix}.investigation_steps"),
        containment_actions=_items(f"{prefix}.containment_actions"),
        limitations=_items(f"{prefix}.limitations"),
    )


COMMON_LIMITATIONS = _items("playbook.common_limitations")
PLAYBOOKS: dict[str, Playbook] = {key: _playbook(key) for key in PLAYBOOK_KEYS}


def get_playbook(key: str) -> Playbook:
    return PLAYBOOKS.get(key) or PLAYBOOKS[key.split(":")[0]]
