"""Load scam rules and score a job advert.

Rules live in ``rules.json``. Matching is local and does not use the network.
A rule fires when any of its patterns match, when an amount check clears its
minimum, or when a long advert is missing every trace of a company or address.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Thousands may be grouped with a space or comma. An optional decimal part
# covers amounts such as R350.00. The non-capturing group keeps "|" local.
AMOUNT_TOKEN = r"(?:(?:\d{1,3}(?:[ \t,]\d{3})+|\d+)(?:[.,]\d{1,2})?)"

DEFAULT_RULES_PATH = Path(__file__).with_name("rules.json")

# A full stop ends a sentence. A decimal point (R28.50) does not.
_SENTENCE_BOUNDARY = re.compile(r"[!?\n]|\.(?!\d)(?=\s|$)")


class RuleFileError(ValueError):
    """The rules file is missing, malformed, or internally inconsistent."""


@dataclass(frozen=True)
class Band:
    name: str
    max: int


@dataclass(frozen=True)
class AmountCheck:
    compiled: re.Pattern[str]
    minimum: int
    group: int


@dataclass(frozen=True)
class MissingCheck:
    compiled: tuple[re.Pattern[str], ...]
    min_length: int
    snippet: str


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    weight: int
    explanation: str
    patterns: tuple[re.Pattern[str], ...]
    amount_checks: tuple[AmountCheck, ...]
    skip_sentence: re.Pattern[str] | None
    missing: MissingCheck | None


@dataclass(frozen=True)
class RuleSet:
    score_cap: int
    bands: tuple[Band, ...]
    next_steps: tuple[str, ...]
    disclaimer: str
    rules: tuple[Rule, ...]


@dataclass(frozen=True)
class Flag:
    id: str
    name: str
    weight: int
    explanation: str
    snippets: tuple[str, ...]


@dataclass(frozen=True)
class Report:
    score: int
    score_cap: int
    weight_total: int
    band: str
    flags: tuple[Flag, ...]
    next_steps: tuple[str, ...]
    warnings: tuple[str, ...]
    disclaimer: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "score_cap": self.score_cap,
            "weight_total": self.weight_total,
            "band": self.band,
            "flags": [
                {
                    "id": flag.id,
                    "name": flag.name,
                    "weight": flag.weight,
                    "explanation": flag.explanation,
                    "snippets": list(flag.snippets),
                }
                for flag in self.flags
            ],
            "next_steps": list(self.next_steps),
            "warnings": list(self.warnings),
            "disclaimer": self.disclaimer,
        }


def load_rules(path: Path | None = None) -> RuleSet:
    """Read and validate a rules file. The packaged file is the default."""
    rules_path = Path(path) if path is not None else DEFAULT_RULES_PATH
    try:
        raw = rules_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuleFileError(f"Could not read rules file {rules_path}: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuleFileError(f"Rules file {rules_path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise RuleFileError("Rules file must contain a JSON object")
    return ruleset_from_dict(data)


def ruleset_from_dict(data: dict[str, Any]) -> RuleSet:
    """Build a rule set from an already-parsed object. Used by tests too."""
    score_cap = _require_int(data.get("score_cap", 100), "score_cap")
    if score_cap < 1:
        raise RuleFileError("score_cap must be at least 1")

    bands = _parse_bands(data.get("bands"), score_cap)
    next_steps = _require_str_list(data.get("next_steps"), "next_steps")
    disclaimer = data.get("disclaimer")
    if not isinstance(disclaimer, str) or not disclaimer.strip():
        raise RuleFileError("disclaimer must be a non-empty string")

    raw_rules = data.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise RuleFileError("rules must be a non-empty list")

    rules: list[Rule] = []
    seen: set[str] = set()
    for entry in raw_rules:
        rule = _parse_rule(entry)
        if rule.id in seen:
            raise RuleFileError(f"Duplicate rule id {rule.id!r}")
        seen.add(rule.id)
        rules.append(rule)

    return RuleSet(
        score_cap=score_cap,
        bands=tuple(bands),
        next_steps=tuple(next_steps),
        disclaimer=disclaimer.strip(),
        rules=tuple(rules),
    )


def analyze(text: str, ruleset: RuleSet | None = None) -> Report:
    """Score advert text. ``text`` is matched locally against ``ruleset``."""
    active = ruleset if ruleset is not None else load_rules()
    normalised = text.replace("\ufeff", "").replace("\u00a0", " ").replace("\r\n", "\n")
    warnings: list[str] = []
    if not normalised.strip():
        warnings.append("The ad text is empty.")

    flags: list[Flag] = []
    for rule in active.rules:
        snippets = _match_rule(rule, normalised)
        if snippets:
            flags.append(
                Flag(
                    id=rule.id,
                    name=rule.name,
                    weight=rule.weight,
                    explanation=rule.explanation,
                    snippets=tuple(snippets),
                )
            )

    flags.sort(key=lambda flag: (-flag.weight, flag.name))
    weight_total = sum(flag.weight for flag in flags)
    score = min(active.score_cap, weight_total)
    return Report(
        score=score,
        score_cap=active.score_cap,
        weight_total=weight_total,
        band=_band_for(score, active.bands),
        flags=tuple(flags),
        next_steps=active.next_steps,
        warnings=tuple(warnings),
        disclaimer=active.disclaimer,
    )


def parse_amount(raw: str) -> int | None:
    """Parse a rand amount. Spaces and thousands separators are ignored."""
    cleaned = raw.strip().replace(" ", "").replace("\u00a0", "")
    if not cleaned:
        return None
    if "," in cleaned and "." in cleaned:
        if cleaned.rfind(".") > cleaned.rfind(","):
            cleaned = cleaned.replace(",", "")
        else:
            cleaned = cleaned.replace(".", "").replace(",", ".")
    elif "," in cleaned:
        parts = cleaned.split(",")
        if all(len(part) == 3 for part in parts[1:]):
            cleaned = "".join(parts)
        else:
            cleaned = cleaned.replace(",", ".")
    elif "." in cleaned:
        parts = cleaned.split(".")
        if all(len(part) == 3 for part in parts[1:]):
            cleaned = "".join(parts)
    try:
        value = float(cleaned)
    except ValueError:
        return None
    if value < 0:
        return None
    return int(value)


def _parse_bands(raw: Any, score_cap: int) -> list[Band]:
    if not isinstance(raw, list) or not raw:
        raise RuleFileError("bands must be a non-empty list")
    bands: list[Band] = []
    previous = -1
    for entry in raw:
        if not isinstance(entry, dict):
            raise RuleFileError("each band must be an object")
        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            raise RuleFileError("each band needs a name")
        maximum = _require_int(entry.get("max"), f"band {name!r} max")
        if maximum <= previous:
            raise RuleFileError("band max values must increase")
        previous = maximum
        bands.append(Band(name=name.strip(), max=maximum))
    if bands[-1].max < score_cap:
        raise RuleFileError("the highest band max must cover score_cap")
    return bands


def _parse_rule(entry: Any) -> Rule:
    if not isinstance(entry, dict):
        raise RuleFileError("each rule must be an object")
    rule_id = entry.get("id")
    name = entry.get("name")
    explanation = entry.get("explanation")
    if not isinstance(rule_id, str) or not re.fullmatch(r"[a-z0-9_]+", rule_id):
        raise RuleFileError(f"invalid rule id {rule_id!r}")
    if not isinstance(name, str) or not name.strip():
        raise RuleFileError(f"rule {rule_id!r} needs a name")
    if not isinstance(explanation, str) or not explanation.strip():
        raise RuleFileError(f"rule {rule_id!r} needs an explanation")
    weight = _require_int(entry.get("weight"), f"rule {rule_id!r} weight")
    if not 1 <= weight <= 100:
        raise RuleFileError(f"rule {rule_id!r} weight must be from 1 to 100")

    patterns = tuple(
        _compile(rule_id, pattern)
        for pattern in _require_str_list(entry.get("patterns", []), f"rule {rule_id!r} patterns")
    )
    amount_checks = tuple(
        _parse_amount_check(rule_id, item) for item in _optional_list(entry.get("amount_checks"), rule_id)
    )
    skip_raw = entry.get("skip_sentence")
    skip_sentence = None
    if skip_raw is not None:
        if not isinstance(skip_raw, str):
            raise RuleFileError(f"rule {rule_id!r} skip_sentence must be a string")
        skip_sentence = _compile(rule_id, skip_raw)

    missing = _parse_missing(rule_id, entry.get("missing"))
    if not patterns and not amount_checks and missing is None:
        raise RuleFileError(f"rule {rule_id!r} has nothing to match")

    return Rule(
        id=rule_id,
        name=name.strip(),
        weight=weight,
        explanation=re.sub(r"\s+", " ", explanation).strip(),
        patterns=patterns,
        amount_checks=amount_checks,
        skip_sentence=skip_sentence,
        missing=missing,
    )


def _parse_amount_check(rule_id: str, item: Any) -> AmountCheck:
    if not isinstance(item, dict):
        raise RuleFileError(f"rule {rule_id!r} amount_checks entries must be objects")
    pattern = item.get("pattern")
    if not isinstance(pattern, str):
        raise RuleFileError(f"rule {rule_id!r} amount check needs a pattern")
    minimum = _require_int(item.get("minimum"), f"rule {rule_id!r} amount minimum")
    if minimum < 0:
        raise RuleFileError(f"rule {rule_id!r} amount minimum cannot be negative")
    group = _require_int(item.get("group", 1), f"rule {rule_id!r} amount group")
    compiled = _compile(rule_id, pattern)
    if compiled.groups < group or group < 1:
        raise RuleFileError(
            f"rule {rule_id!r} amount pattern must have capturing group {group}"
        )
    return AmountCheck(compiled=compiled, minimum=minimum, group=group)


def _parse_missing(rule_id: str, raw: Any) -> MissingCheck | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise RuleFileError(f"rule {rule_id!r} missing must be an object")
    patterns = _require_str_list(raw.get("patterns"), f"rule {rule_id!r} missing patterns")
    if not patterns:
        raise RuleFileError(f"rule {rule_id!r} missing patterns must not be empty")
    min_length = _require_int(raw.get("min_length", 1), f"rule {rule_id!r} missing min_length")
    snippet = raw.get("snippet")
    if not isinstance(snippet, str) or not snippet.strip():
        raise RuleFileError(f"rule {rule_id!r} missing check needs a snippet")
    return MissingCheck(
        compiled=tuple(_compile(rule_id, pattern) for pattern in patterns),
        min_length=min_length,
        snippet=snippet.strip(),
    )


def _compile(rule_id: str, pattern: str) -> re.Pattern[str]:
    concrete = pattern.replace("{amount}", AMOUNT_TOKEN)
    try:
        return re.compile(concrete)
    except re.error as exc:
        raise RuleFileError(
            f"rule {rule_id!r} has an invalid pattern {pattern!r}: {exc}"
        ) from exc


def _match_rule(rule: Rule, text: str) -> list[str]:
    found: list[str] = []
    for pattern in rule.patterns:
        for match in pattern.finditer(text):
            if _sentence_skipped(rule, text, match.start(), match.end()):
                continue
            found.append(_snippet_for(text, match.start(), match.end()))
    for check in rule.amount_checks:
        for match in check.compiled.finditer(text):
            if _sentence_skipped(rule, text, match.start(), match.end()):
                continue
            amount = parse_amount(match.group(check.group))
            if amount is None or amount < check.minimum:
                continue
            found.append(_snippet_for(text, match.start(), match.end()))
    unique = _dedupe(found)
    if unique:
        return unique[:5]
    if rule.missing is None or len(text.strip()) < rule.missing.min_length:
        return []
    if any(pattern.search(text) for pattern in rule.missing.compiled):
        return []
    return [rule.missing.snippet]


def _sentence_bounds(text: str, start: int, end: int) -> tuple[int, int]:
    left = 0
    for boundary in _SENTENCE_BOUNDARY.finditer(text, 0, start):
        left = boundary.end()
    right_boundary = _SENTENCE_BOUNDARY.search(text, end)
    right = right_boundary.start() if right_boundary else len(text)
    return left, right


def _sentence_skipped(rule: Rule, text: str, start: int, end: int) -> bool:
    if rule.skip_sentence is None:
        return False
    left, right = _sentence_bounds(text, start, end)
    return rule.skip_sentence.search(text[left:right]) is not None


def _snippet_for(text: str, start: int, end: int) -> str:
    """Prefer the whole sentence so the reader sees the matched words in place."""
    left, right = _sentence_bounds(text, start, end)
    sentence = _compact(text[left:right])
    matched = _compact(text[start:end])
    if sentence and len(sentence) <= 160 and matched in sentence:
        return sentence
    window_left = start
    window_right = end
    if end - start < 48:
        window_left = max(0, start - 40)
        window_right = min(len(text), end + 40)
        if window_left > 0:
            space = text.rfind(" ", window_left, start)
            if space != -1:
                window_left = space + 1
        if window_right < len(text):
            space = text.find(" ", end, window_right)
            if space != -1:
                window_right = space
    snippet = _clean_snippet(text[window_left:window_right])
    if window_left > 0:
        snippet = "..." + snippet
    if window_right < len(text):
        snippet = snippet + "..."
    return snippet


def _compact(snippet: str) -> str:
    return re.sub(r"\s+", " ", snippet).strip()


def _clean_snippet(snippet: str) -> str:
    compact = _compact(snippet)
    if len(compact) > 160:
        return compact[:157].rstrip() + "..."
    return compact


def _dedupe(snippets: list[str]) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    for snippet in snippets:
        key = snippet.casefold()
        if key in seen:
            continue
        seen.add(key)
        unique.append(snippet)
    return unique


def _band_for(score: int, bands: tuple[Band, ...]) -> str:
    for band in bands:
        if score <= band.max:
            return band.name
    return bands[-1].name


def _require_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RuleFileError(f"{label} must be an integer")
    return value


def _require_str_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise RuleFileError(f"{label} must be a list of strings")
    return value


def _optional_list(value: Any, rule_id: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise RuleFileError(f"rule {rule_id!r} amount_checks must be a list")
    return value
