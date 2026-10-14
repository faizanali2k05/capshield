from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any


DEFAULT_SENSITIVE_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "authorization",
        "cookie",
        "client_secret",
        "password",
        "private_key",
        "refresh_token",
        "secret",
        "set-cookie",
        "token",
        "x-api-key",
    }
)


@dataclass(frozen=True)
class RedactionPolicy:
    """Reusable redaction rules for structured diagnostic payloads."""

    keys: frozenset[str] = field(default_factory=lambda: DEFAULT_SENSITIVE_KEYS)
    paths: frozenset[tuple[str, ...]] = field(default_factory=frozenset)
    replacement: str = "[REDACTED]"
    cycle_replacement: str = "[CYCLE]"
    max_depth: int = 20

    def apply(self, value: Any) -> Any:
        return redact(
            value,
            keys=self.keys,
            paths=self.paths,
            replacement=self.replacement,
            cycle_replacement=self.cycle_replacement,
            max_depth=self.max_depth,
        )


def redact(
    value: Any,
    *,
    keys: Iterable[str] = DEFAULT_SENSITIVE_KEYS,
    paths: set[tuple[str, ...]] | frozenset[tuple[str, ...]] = frozenset(),
    replacement: str = "[REDACTED]",
    cycle_replacement: str = "[CYCLE]",
    max_depth: int = 20,
) -> Any:
    """Return a copy with sensitive keys or exact tuple paths replaced.

    Mapping keys are matched case-insensitively. Exact paths are represented
    as tuples, with sequence indexes expressed as strings. Cyclic structures
    are replaced with ``cycle_replacement`` instead of recursing forever.
    """

    if max_depth < 0:
        raise ValueError("max_depth must be non-negative")
    keyset = {key.lower() for key in keys}
    pathset = set(paths)
    active: set[int] = set()

    def visit(item: Any, path: tuple[str, ...], depth: int) -> Any:
        if path in pathset:
            return replacement
        if depth > max_depth:
            return "[DEPTH_LIMIT]"
        if isinstance(item, Mapping):
            identity = id(item)
            if identity in active:
                return cycle_replacement
            active.add(identity)
            try:
                return {
                    key: replacement
                    if str(key).lower() in keyset
                    else visit(child, path + (str(key),), depth + 1)
                    for key, child in item.items()
                }
            finally:
                active.remove(identity)
        if isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            identity = id(item)
            if identity in active:
                return cycle_replacement
            active.add(identity)
            try:
                return [visit(child, path + (str(index),), depth + 1) for index, child in enumerate(item)]
            finally:
                active.remove(identity)
        if isinstance(item, (bytes, bytearray)):
            return f"<bytes:{len(item)}>"
        return item

    return visit(value, (), 0)
