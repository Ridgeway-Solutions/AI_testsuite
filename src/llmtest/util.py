"""Shared helpers: rate limiting, retries, text normalisation, redaction."""

from __future__ import annotations

import asyncio
import random
import re
import time
import unicodedata
import urllib.parse
from typing import Any


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


_WS = re.compile(r"\s+")
_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿"))


def normalize(text: str) -> str:
    """Fold text for matching: NFKC, strip zero-width, collapse whitespace, lower."""
    text = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)
    return _WS.sub(" ", text).strip().lower()


def truncate(text: str, limit: int = 400) -> str:
    text = text.strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


# Best-effort, prefix-based. This is a backstop for text we cannot inspect
# ahead of time, not a guarantee — the primary defence against publishing a
# credential is the allowlist in Target.describe().
_SECRET_PATTERNS = [
    re.compile(r"\b(sk-[A-Za-z0-9_\-]{16,})"),                 # OpenAI-style
    re.compile(r"\b(ghp_[A-Za-z0-9]{20,})"),                   # GitHub PAT
    re.compile(r"\b(glpat-[A-Za-z0-9_\-]{16,})"),              # GitLab PAT
    re.compile(r"\b(xox[baprs]-[A-Za-z0-9\-]{10,})"),          # Slack
    re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),                     # AWS access key id
    re.compile(r"\b(AIza[0-9A-Za-z_\-]{30,})"),                # Google API key
    # A credential-shaped value assigned to a credential-shaped name.
    re.compile(
        r"(?i)\b(?:api[_-]?key|access[_-]?token|authorization|bearer|token|secret"
        r"|password|passwd|credential)\b\s*[:=]?\s*['\"]?([A-Za-z0-9._\-]{16,})"
    ),
]


def redact(text: str) -> str:
    """Strip credential-shaped strings before anything is written to a report."""
    for pat in _SECRET_PATTERNS:
        text = pat.sub(lambda m: m.group(0).replace(m.group(1), "[REDACTED]"), text)
    return text


def redact_tree(node: Any) -> Any:
    """Apply :func:`redact` to every string in a nested structure.

    Redacting one field by hand is how the gaps appear: a report grows a new
    text field and nobody remembers it also carries model output.
    """
    if isinstance(node, str):
        return redact(node)
    if isinstance(node, dict):
        return {k: redact_tree(v) for k, v in node.items()}
    if isinstance(node, (list, tuple)):
        return [redact_tree(v) for v in node]
    return node


def safe_url(url: str) -> str:
    """A URL with credentials removed, for display in a report.

    Query strings and userinfo carry API keys often enough that echoing a
    configured endpoint verbatim is a way to leak one into a shared artefact.
    """
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return "[unparseable url]"
    if not parts.scheme and not parts.netloc:
        return url
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    cleaned = urllib.parse.urlunsplit((parts.scheme, host, parts.path, "", ""))
    if parts.query:
        cleaned += "?[redacted]"
    return cleaned


def stable_rng(*parts: object) -> random.Random:
    """Deterministic RNG seeded from the given parts, so runs are reproducible."""
    return random.Random("|".join(str(p) for p in parts))
