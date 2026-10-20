"""Normalize IAM policy documents so the lint rules see one shape.

IAM accepts many spellings of the same thing: ``Statement`` as an object or a
list, ``Action`` as a string or a list, condition values as strings, booleans
or lists, and condition keys in any case. Everything is normalized here once.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Any


class PolicyError(ValueError):
    """The document is not a valid IAM policy (bad JSON or wrong shape)."""


def _as_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, list | tuple):
        return tuple(str(v) for v in value)
    if isinstance(value, bool):
        return ("true" if value else "false",)
    return (str(value),)


@dataclass(frozen=True)
class Statement:
    sid: str
    effect: str
    actions: tuple[str, ...] = ()
    not_actions: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()
    not_resources: tuple[str, ...] = ()
    principals: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    not_principal: bool = False
    # operator -> lower-cased condition key -> values
    conditions: Mapping[str, Mapping[str, tuple[str, ...]]] = field(default_factory=dict)

    @property
    def allows(self) -> bool:
        return self.effect == "Allow"

    def condition(self, key: str) -> list[tuple[str, tuple[str, ...]]]:
        """Every (operator, values) pair that tests ``key`` (case-insensitive)."""
        wanted = key.lower()
        return [
            (op, values)
            for op, keys in self.conditions.items()
            for k, values in keys.items()
            if k == wanted
        ]

    def has_condition(self, key: str) -> bool:
        return bool(self.condition(key))

    def grants(self, action: str) -> bool:
        """True if this statement's Action list covers ``action`` (IAM wildcards)."""
        return any(action_matches(pattern, action) for pattern in self.actions)


def action_matches(pattern: str, action: str) -> bool:
    """IAM action matching: case-insensitive, ``*`` and ``?`` wildcards."""
    return fnmatchcase(action.lower(), pattern.lower())


def load_document(doc: str | Mapping[str, Any]) -> Mapping[str, Any]:
    if isinstance(doc, str):
        try:
            parsed = json.loads(doc)
        except json.JSONDecodeError as exc:
            raise PolicyError(f"not valid JSON: {exc}") from exc
    else:
        parsed = doc
    if not isinstance(parsed, Mapping) or "Statement" not in parsed:
        raise PolicyError("not an IAM policy: no Statement")
    return parsed


def parse_statements(doc: str | Mapping[str, Any]) -> list[Statement]:
    raw = load_document(doc)["Statement"]
    items = raw if isinstance(raw, list) else [raw]
    out: list[Statement] = []
    for i, st in enumerate(items):
        if not isinstance(st, Mapping) or st.get("Effect") not in ("Allow", "Deny"):
            raise PolicyError(f"statement {i}: missing or invalid Effect")
        out.append(
            Statement(
                sid=str(st.get("Sid") or f"#{i}"),
                effect=str(st["Effect"]),
                actions=_as_tuple(st.get("Action")),
                not_actions=_as_tuple(st.get("NotAction")),
                resources=_as_tuple(st.get("Resource")),
                not_resources=_as_tuple(st.get("NotResource")),
                principals=_principals(st.get("Principal", st.get("NotPrincipal"))),
                not_principal="NotPrincipal" in st,
                conditions=_conditions(st.get("Condition")),
            )
        )
    return out


def _principals(value: Any) -> dict[str, tuple[str, ...]]:
    if value is None:
        return {}
    if value == "*":
        return {"*": ("*",)}
    if not isinstance(value, Mapping):
        raise PolicyError(f"invalid Principal: {value!r}")
    return {str(kind): _as_tuple(ids) for kind, ids in value.items()}


def _conditions(value: Any) -> dict[str, dict[str, tuple[str, ...]]]:
    if not value:
        return {}
    if not isinstance(value, Mapping):
        raise PolicyError(f"invalid Condition: {value!r}")
    out: dict[str, dict[str, tuple[str, ...]]] = {}
    for op, keys in value.items():
        if not isinstance(keys, Mapping):
            raise PolicyError(f"invalid Condition block for {op}")
        out[str(op)] = {str(k).lower(): _as_tuple(v) for k, v in keys.items()}
    return out
