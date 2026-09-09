"""Shared helpers: rate limiting, retries, text normalisation, redaction."""

from __future__ import annotations

import asyncio
import random
import re
import time
import unicodedata
from typing import Awaitable, Callable, TypeVar

T = TypeVar("T")


class RateLimiter:
    """Token bucket. ``rps <= 0`` disables limiting."""

    def __init__(self, rps: float, burst: int | None = None) -> None:
        self.rps = rps
        self.capacity = burst if burst is not None else max(1, int(rps))
        self._tokens = float(self.capacity)
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if self.rps <= 0:
            return
        async with self._lock:
            while True:
                now = time.monotonic()
                self._tokens = min(
                    self.capacity, self._tokens + (now - self._updated) * self.rps
                )
                self._updated = now
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                await asyncio.sleep((1 - self._tokens) / self.rps)


async def retry_async(
    fn: Callable[[], Awaitable[T]],
    *,
    attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 16.0,
    retry_on: Callable[[BaseException], bool] = lambda e: True,
) -> T:
    """Exponential backoff with full jitter."""
    last: BaseException | None = None
    for i in range(attempts):
        try:
            return await fn()
        except asyncio.CancelledError:
            raise
        except BaseException as exc:  # noqa: BLE001 - re-raised below
            if not retry_on(exc) or i == attempts - 1:
                raise
            last = exc
            delay = min(max_delay, base_delay * (2**i))
            await asyncio.sleep(random.uniform(0, delay))
    raise last  # pragma: no cover - unreachable


_WS = re.compile(r"\s+")
_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿"))


def normalize(text: str) -> str:
    """Fold text for matching: NFKC, strip zero-width, collapse whitespace, lower."""
    text = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)
    return _WS.sub(" ", text).strip().lower()


def truncate(text: str, limit: int = 400) -> str:
    text = text.strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


_SECRET_PATTERNS = [
    re.compile(r"\b(sk-[A-Za-z0-9_\-]{16,})"),
    re.compile(r"\b(ghp_[A-Za-z0-9]{20,})"),
    re.compile(r"\b(xox[baprs]-[A-Za-z0-9\-]{10,})"),
    re.compile(r"(?i)\b(?:api[_-]?key|authorization|bearer)\b\s*[:=]?\s*([A-Za-z0-9._\-]{16,})"),
]


def redact(text: str) -> str:
    """Strip credential-shaped strings before anything is written to a report."""
    for pat in _SECRET_PATTERNS:
        text = pat.sub(lambda m: m.group(0).replace(m.group(1), "[REDACTED]"), text)
    return text


def stable_rng(*parts: object) -> random.Random:
    """Deterministic RNG seeded from the given parts, so runs are reproducible."""
    return random.Random("|".join(str(p) for p in parts))
