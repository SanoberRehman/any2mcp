"""Append-only JSONL record of every tool invocation.

Privacy default: argument *names and types* are recorded, not their values.
Tool arguments routinely carry API keys, file contents, and personal data, and a
log that silently copied them to disk would be a new vulnerability rather than a
safety feature. Pass ``--audit-values`` to include truncated values when you
have decided that is appropriate for your data.

The wrapper preserves ``__wrapped__``, ``__annotations__`` and the original
signature, so the MCP SDK still derives the same JSON schema it would have
derived from the undecorated function.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import json
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_MAX_VALUE_CHARS = 200


class AuditLog:
    """Writes one JSON object per line. Never raises into the tool call."""

    def __init__(self, path: str | Path | None, *, record_values: bool = False) -> None:
        self.path = Path(path) if path else None
        self.record_values = record_values
        self._lock = threading.Lock()
        self._broken = False

    @property
    def enabled(self) -> bool:
        return self.path is not None

    def write(self, event: dict[str, Any]) -> None:
        if self.path is None or self._broken:
            return
        payload = {"ts": _now(), **event}
        line = json.dumps(payload, default=_stringify, ensure_ascii=False)
        try:
            with self._lock:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
        except OSError:
            # A broken log must not take down a working server. Degrade once,
            # stay quiet after that.
            self._broken = True

    def record_startup(self, event: dict[str, Any]) -> None:
        self.write({"event": "startup", **event})

    def record_blocked(self, name: str, reason: str, level: str) -> None:
        self.write(
            {"event": "blocked", "tool": name, "risk": level, "reason": reason}
        )

    def wrap(self, func: Callable[..., Any], name: str, level: str) -> Callable[..., Any]:
        """Return *func* instrumented to log each call, preserving its signature."""
        if not self.enabled:
            return func

        if inspect.iscoroutinefunction(func) or asyncio.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                started = time.perf_counter()
                try:
                    result = await func(*args, **kwargs)
                except BaseException as exc:
                    self._finish(name, level, args, kwargs, started, exc)
                    raise
                self._finish(name, level, args, kwargs, started, None)
                return result

            return async_wrapper

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            started = time.perf_counter()
            try:
                result = func(*args, **kwargs)
            except BaseException as exc:
                self._finish(name, level, args, kwargs, started, exc)
                raise
            self._finish(name, level, args, kwargs, started, None)
            return result

        return wrapper

    def _finish(
        self,
        name: str,
        level: str,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        started: float,
        error: BaseException | None,
    ) -> None:
        event: dict[str, Any] = {
            "event": "call",
            "tool": name,
            "risk": level,
            "duration_ms": round((time.perf_counter() - started) * 1000, 3),
            "ok": error is None,
            "args": self._describe(args, kwargs),
        }
        if error is not None:
            event["error"] = f"{type(error).__name__}: {error}"
        self.write(event)

    def _describe(
        self, args: tuple[Any, ...], kwargs: dict[str, Any]
    ) -> dict[str, Any]:
        described: dict[str, Any] = {}
        for index, value in enumerate(args):
            described[f"arg{index}"] = self._describe_one(value)
        for key, value in kwargs.items():
            described[key] = self._describe_one(value)
        return described

    def _describe_one(self, value: Any) -> Any:
        if not self.record_values:
            return type(value).__name__
        text = repr(value)
        if len(text) > _MAX_VALUE_CHARS:
            text = text[:_MAX_VALUE_CHARS] + f"...<truncated {len(text)} chars>"
        return {"type": type(value).__name__, "value": text}


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def _stringify(obj: Any) -> str:
    return repr(obj)
