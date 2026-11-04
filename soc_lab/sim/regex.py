"""POSIX regular expressions (grep, sed, awk, find) translated to Python's `re`.

Basic regular expressions (grep, sed): ( ) { } | + ? are literal unless escaped. Extended ones
(grep -E, awk, sed -E): they are operators. Bracket classes such as [[:digit:]] and the GNU word
boundaries \\< \\> are translated too.
"""

from __future__ import annotations

import re

from .core import ShellError

CLASSES = {
    "alpha": "a-zA-Z", "digit": "0-9", "alnum": "a-zA-Z0-9", "upper": "A-Z", "lower": "a-z",
    "space": r" \t\n\r\f\v", "blank": r" \t", "punct": r"!-/:-@\[-`{-~", "xdigit": "0-9A-Fa-f",
    "word": r"\w", "cntrl": r"\x00-\x1f",
}


def _bracket(pattern: str, i: int) -> tuple[str, int]:
    """Translate a bracket expression starting at pattern[i] == '['; returns (python text, next index)."""
    out = ["["]
    i += 1
    if i < len(pattern) and pattern[i] == "^":
        out.append("^")
        i += 1
    first = True
    while i < len(pattern):
        ch = pattern[i]
        if ch == "]" and not first:
            out.append("]")
            return "".join(out), i + 1
        if pattern.startswith("[:", i):
            end = pattern.find(":]", i + 2)
            name = pattern[i + 2:end] if end != -1 else ""
            if name in CLASSES:
                out.append(CLASSES[name])
                i = end + 2
                first = False
                continue
        if ch in "\\[]^":
            out.append("\\" + ch)
        else:
            out.append(ch)
        first = False
        i += 1
    raise ShellError("Unmatched [, [^, [:, [., or [=")


def to_python(pattern: str, extended: bool = False) -> str:
    out = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "[":
            text, i = _bracket(pattern, i)
            out.append(text)
            continue
        if ch == "\\" and i + 1 < len(pattern):
            nxt = pattern[i + 1]
            i += 2
            if nxt in "<>":
                out.append(r"\b")
            elif not extended and nxt in "(){}|+?":
                out.append(nxt)
            elif nxt in "wWsSbB":
                out.append("\\" + nxt)
            elif nxt.isdigit():
                out.append("\\" + nxt)
            elif nxt == "t":
                out.append(r"\t")
            elif nxt == "n":
                out.append(r"\n")
            else:
                out.append(re.escape(nxt))
            continue
        if not extended and ch in "(){}|+?":
            out.append("\\" + ch)
        elif not extended and ch == "*" and (not out or out[-1] in ("^", "(")):
            out.append(r"\*")
        elif extended and ch == "{" and not re.match(r"\{\d*(,\d*)?\}", pattern[i:]):
            out.append(r"\{")
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def compile_posix(pattern: str, extended: bool = False, ignore_case: bool = False) -> re.Pattern:
    try:
        return re.compile(to_python(pattern, extended), re.IGNORECASE if ignore_case else 0)
    except re.error as exc:
        raise ShellError(f"Invalid regular expression: {exc}") from exc
