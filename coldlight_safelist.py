#!/usr/bin/env python3
"""
Safe-list matching for the ColdLight awareness test.

Excludes opted-out people and sensitive identities (executives, service accounts,
anyone who asked not to be tested) so they are never counted. Patterns are
case-insensitive glob (fnmatch) and may be scoped:

    host:WS-CEO-*     match the hostname only
    user:svc-*        match the username only
    jdoe              bare pattern matches EITHER hostname or username

One pattern per line in a file (``#`` comments allowed), or a list in config.

Note: if you put the safe-list in the payload config, the patterns are baked
onto the USB. Prefer the collector-side safe-list (kept on your server), and use
role/prefix patterns rather than full personal names to limit exposure.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path


def load_patterns(path: str | Path) -> list[str]:
    """Read patterns from a file, skipping blanks and ``#`` comments."""
    out: list[str] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def matches(patterns: list[str] | None, hostname: str = "", username: str = "") -> bool:
    """True if this host/user is covered by any safe-list pattern."""
    host = (hostname or "").lower()
    user = (username or "").lower()
    for raw in patterns or []:
        p = raw.strip().lower()
        if not p:
            continue
        if p.startswith("host:"):
            if fnmatch.fnmatch(host, p[5:]):
                return True
        elif p.startswith("user:"):
            if fnmatch.fnmatch(user, p[5:]):
                return True
        elif fnmatch.fnmatch(host, p) or fnmatch.fnmatch(user, p):
            return True
    return False
