"""Translations for everything the analyst reads (interface, alerts, playbooks, reports).

Texts live in `soc_lab/locales/<language>.json`, one flat {key: text} file per language.
English (`en.json`) is the reference: every key must exist there, and any key missing from
another language falls back to English. To add a language, copy `en.json`, translate the
values (keep the `{placeholders}`) and register it in LANGUAGES.

Detection rules and reports build their sentences as `Msg` objects. A Msg *is* the English
string (so CSV exports, the CLI and string comparisons keep working unchanged) but it also
remembers its key and values, so the dashboard can render the same sentence in another language.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

LOCALES_DIR = Path(__file__).resolve().parent / "locales"
LANGUAGES = {"en": "EN", "pt-BR": "PT-BR"}  # code -> label shown in the language selector
DEFAULT_LANGUAGE = "en"


@lru_cache(maxsize=None)
def catalog(lang: str) -> dict[str, str]:
    """All texts for one language. Unknown language -> empty catalog (everything falls back to English)."""
    path = LOCALES_DIR / f"{lang}.json"
    if lang not in LANGUAGES or not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def text_for(key: str, lang: str) -> str:
    """Raw (unformatted) text for a key, falling back to English. Unknown key -> KeyError."""
    return catalog(lang).get(key) or catalog(DEFAULT_LANGUAGE)[key]


def has_key(key: str) -> bool:
    return key in catalog(DEFAULT_LANGUAGE)


def t(key: str, lang: str = DEFAULT_LANGUAGE, **params) -> str:
    """Translated text for `key`, with `{placeholders}` filled from params (Msg values are translated too)."""
    text = text_for(key, lang)
    return text.format(**{name: tr(value, lang) for name, value in params.items()}) if params else text


def tr(value, lang: str = DEFAULT_LANGUAGE):
    """Render a Msg in `lang`. Anything else (plain strings from the data, numbers) is returned unchanged."""
    return value.render(lang) if isinstance(value, Msg) else value


def keys_with_prefix(prefix: str) -> list[str]:
    """Numbered keys `prefix.1`, `prefix.2`, ... in order - used for lists such as playbook steps."""
    keys, number = [], 1
    while has_key(f"{prefix}.{number}"):
        keys.append(f"{prefix}.{number}")
        number += 1
    return keys


class Msg(str):
    """English text that can be re-rendered in another language.

    `Msg("r001.title", user="j.smith")` equals the English sentence, and `.render("pt-BR")`
    builds the same sentence, with the same values, in Portuguese.
    """

    key: str | None
    params: dict

    def __new__(cls, key: str, **params):
        msg = super().__new__(cls, t(key, DEFAULT_LANGUAGE, **params))
        msg.key, msg.params = key, params
        return msg

    @classmethod
    def join(cls, parts, sep: str = " ") -> "Msg":
        """Several messages joined by `sep`, each one translated on its own."""
        parts = tuple(parts)
        msg = str.__new__(cls, sep.join(parts))
        msg.key, msg.params = None, {"parts": parts, "sep": sep}
        return msg

    def render(self, lang: str) -> str:
        if self.key is None:
            return self.params["sep"].join(str(tr(part, lang)) for part in self.params["parts"])
        return t(self.key, lang, **self.params)

    def __reduce__(self):  # pickling (Streamlit's cache) must rebuild from key + values, not from the text
        return _rebuild, (self.key, self.params)


def _rebuild(key: str | None, params: dict) -> Msg:
    return Msg.join(params["parts"], params["sep"]) if key is None else Msg(key, **params)
