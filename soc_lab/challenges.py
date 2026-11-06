"""Terminal challenges: load, check answers and keep progress.

The challenges live in data/terminal/challenges.json, a plain JSON file shared by every phase of
the Terminal tab (bash and PowerShell in Docker, and the simulated bash, PowerShell and CMD), so the
same questions, hints and answers work everywhere. Texts are in the file itself, in every
supported language, so a JavaScript terminal can read it without the Python translation files.

Each challenge also names the topics of the study roadmap (a separate page) that explain it, so a
learner who gets stuck can open the right lesson: the link is the roadmap's url followed by #topic.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path

from .config import PROJECT_ROOT
from .i18n import DEFAULT_LANGUAGE, LANGUAGES

CHALLENGES_PATH = PROJECT_ROOT / "data" / "terminal" / "challenges.json"
ENVIRONMENTS = ("linux", "powershell", "cmd")
TEXT_FIELDS = ("title", "question", "explanation")
ROADMAP_TOPIC_ID = re.compile(r"^[a-z0-9-]+$")  # a plain #name: the only fragment the roadmap page receives


class ChallengeError(ValueError):
    """The challenges file is missing, malformed or inconsistent."""


@dataclass(frozen=True)
class Challenge:
    id: str
    environments: tuple[str, ...]
    level: int
    topic: str
    files: tuple[str, ...]
    title: dict
    question: dict
    hints: tuple[dict, ...]
    answers: tuple[str, ...]
    solution: str
    explanation: dict
    roadmap: tuple[str, ...] = ()  # roadmap topic ids that explain this challenge

    def text(self, field: str, lang: str = DEFAULT_LANGUAGE) -> str:
        values = getattr(self, field)
        return values.get(lang) or values[DEFAULT_LANGUAGE]

    def hint(self, number: int, lang: str = DEFAULT_LANGUAGE) -> str:
        return self.hints[number].get(lang) or self.hints[number][DEFAULT_LANGUAGE]

    def check(self, answer: str) -> bool:
        given = normalise_answer(answer)
        return bool(given) and given in {normalise_answer(expected) for expected in self.answers}


@dataclass(frozen=True)
class ChallengeSet:
    environments: dict  # name -> {"home": ..., "files": {path in terminal: lab file}}
    challenges: tuple[Challenge, ...]
    roadmap: dict | None = None  # {"url": ..., "topics": {id: {lang: name}}}

    def for_environment(self, environment: str) -> list[Challenge]:
        return [c for c in self.challenges if environment in c.environments]

    def files(self, environment: str | None = None, root: Path = PROJECT_ROOT) -> dict[str, Path]:
        """Terminal path (relative to the home directory) -> lab file on disk.

        Without an environment: the files of every environment, since one container serves both shells."""
        names = [environment] if environment else list(self.environments)
        return {path: root / source for name in names for path, source in self.environments[name]["files"].items()}

    def get(self, challenge_id: str) -> Challenge:
        return next(c for c in self.challenges if c.id == challenge_id)

    def find(self, challenge_id: str) -> Challenge | None:
        return next((c for c in self.challenges if c.id == challenge_id), None)

    def roadmap_links(self, challenge: Challenge, lang: str = DEFAULT_LANGUAGE) -> list[tuple[str, str]]:
        """(topic name, link) for each roadmap topic that explains the challenge."""
        if not self.roadmap:
            return []
        topics = self.roadmap["topics"]
        return [(topics[topic].get(lang) or topics[topic][DEFAULT_LANGUAGE], f"{self.roadmap['url']}#{topic}")
                for topic in challenge.roadmap]


def normalise_answer(text: str) -> str:
    """Compare answers loosely: case, accents, surrounding quotes and repeated spaces do not matter."""
    text = unicodedata.normalize("NFKD", str(text)).encode("ascii", "ignore").decode("ascii")
    text = re.sub(r"\s+", " ", text).strip().strip("`'\"").strip()
    return text.casefold()


def load_challenges(path: Path = CHALLENGES_PATH) -> ChallengeSet:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ChallengeError(f"cannot read {path}: {exc}") from exc
    environments = document.get("environments", {})
    challenges = []
    for raw in document.get("challenges", []):
        try:
            challenges.append(Challenge(
                id=raw["id"], environments=tuple(raw["environments"]), level=int(raw["level"]),
                topic=raw["topic"], files=tuple(raw.get("files", [])), title=raw["title"],
                question=raw["question"], hints=tuple(raw.get("hints", [])), answers=tuple(raw["answers"]),
                solution=raw["solution"], explanation=raw["explanation"], roadmap=tuple(raw.get("roadmap", []))))
        except (KeyError, TypeError, ValueError) as exc:
            raise ChallengeError(f"challenge {raw.get('id', '?')}: missing or invalid field ({exc})") from exc
    result = ChallengeSet(environments, tuple(challenges), document.get("roadmap"))
    _validate(result)
    return result


def _validate(challenge_set: ChallengeSet) -> None:
    ids = [c.id for c in challenge_set.challenges]
    if len(ids) != len(set(ids)):
        raise ChallengeError("challenge ids must be unique")
    roadmap = challenge_set.roadmap or {}
    topics = roadmap.get("topics", {})
    if roadmap and not str(roadmap.get("url", "")).startswith("https://"):
        raise ChallengeError("roadmap: 'url' must be an https:// address")
    for topic, names in topics.items():
        if not ROADMAP_TOPIC_ID.match(topic) or DEFAULT_LANGUAGE not in names:
            raise ChallengeError(f"roadmap topic '{topic}': needs a plain lowercase id and a {DEFAULT_LANGUAGE} name")
    for challenge in challenge_set.challenges:
        unknown_topics = set(challenge.roadmap) - set(topics)
        if unknown_topics:
            raise ChallengeError(f"{challenge.id}: unknown roadmap topics {sorted(unknown_topics)}")
        if not challenge.answers or not all(normalise_answer(a) for a in challenge.answers):
            raise ChallengeError(f"{challenge.id}: needs at least one non-empty answer")
        for field in TEXT_FIELDS:
            if DEFAULT_LANGUAGE not in getattr(challenge, field):
                raise ChallengeError(f"{challenge.id}: '{field}' has no {DEFAULT_LANGUAGE} text")
        for environment in challenge.environments:
            if environment not in challenge_set.environments:
                raise ChallengeError(f"{challenge.id}: unknown environment '{environment}'")
            unknown = set(challenge.files) - set(challenge_set.environments[environment]["files"])
            if unknown:
                raise ChallengeError(f"{challenge.id}: files not available in {environment}: {sorted(unknown)}")


# ---------------------------------------------------------------------------
# Progress (one small JSON file next to the training answers)
# ---------------------------------------------------------------------------
def progress_path(base_dir: Path, environment: str) -> Path:
    return Path(base_dir) / f"terminal_{environment}.json"


def load_progress(path: Path) -> dict[str, set[str]]:
    """{"solved": {...ids}, "revealed": {...ids}}; a missing or damaged file means no progress yet."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return {key: set(data.get(key, [])) for key in ("solved", "revealed")}
    except (OSError, ValueError, AttributeError):
        return {"solved": set(), "revealed": set()}


def save_progress(path: Path, progress: dict[str, set[str]]) -> None:
    path = Path(path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({key: sorted(values) for key, values in progress.items()}, indent=2),
                        encoding="utf-8")
    except OSError:
        pass  # read-only places (the in-browser build) keep progress for the session only


def languages_missing(challenge: Challenge) -> list[str]:
    """Languages without a text for some field: these fall back to English."""
    missing = set()
    for lang in LANGUAGES:
        for field in TEXT_FIELDS:
            if lang not in getattr(challenge, field):
                missing.add(lang)
        if any(lang not in hint for hint in challenge.hints):
            missing.add(lang)
    return sorted(missing)
