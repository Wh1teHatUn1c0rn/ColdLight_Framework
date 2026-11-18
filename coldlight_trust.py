#!/usr/bin/env python3
"""
One TLS trust store for the whole tool.

This used to live inside `coldlight_vulnintel`, which made it the vuln-intel
module's private business. Everything that happened to import that module got
the configured trust store; everything that did not quietly used the system
default instead. `coldlight_mail` was in the second group, so `COLDLIGHT_CA_BUNDLE`
fixed NVD and OSV lookups and silently did nothing for `mail audit` -- the
operator had no way to tell which of their network calls honoured it.

A trust store that only applies to some of a tool's connections is worse than
one that applies to none, because it looks like it is working.

So it lives here instead: a module small enough that every network-using part
of ColdLight can import it without pulling anything else in, and with no
fallback path, because there is nothing left for it to fall back from. If this
module cannot be imported, ColdLight has no TLS at all and should say so rather
than silently reaching for a different trust store.

Verification is never weakened here, and there is no option to weaken it. A
stale or missing CA bundle is a configuration problem with a configuration
fix -- point `COLDLIGHT_CA_BUNDLE` at a current bundle, or install certifi.

Stdlib only (certifi is consulted if present, never required).
"""

from __future__ import annotations

import os
import ssl
from pathlib import Path

# Environment variables consulted, in order of precedence.
CA_BUNDLE_VARS = ("COLDLIGHT_CA_BUNDLE", "SSL_CERT_FILE")

_ssl_ctx: ssl.SSLContext | None = None


def ca_bundle() -> str | None:
    """Path to the CA bundle to trust, or None for the system default.

    Order: COLDLIGHT_CA_BUNDLE -> SSL_CERT_FILE -> certifi (if installed).
    Some machines still carry an expired cross-signed root that makes an
    otherwise-valid NVD certificate fail to verify; a current bundle fixes
    that without ever weakening the check.

    A variable pointing at a file that is not there is skipped rather than
    passed to OpenSSL, so a typo degrades to the next source instead of
    breaking every connection. That silence is itself a trap, which is why
    `coldlight doctor` reports an ignored variable rather than leaving the
    operator to wonder why their fix had no effect.
    """
    for var in CA_BUNDLE_VARS:
        path = os.environ.get(var, "").strip()
        if path and Path(path).is_file():
            return path
    try:
        import certifi
        return certifi.where()
    except Exception:  # noqa: BLE001 - certifi is optional
        return None


def ca_bundle_source() -> str:
    """Which of the sources `ca_bundle()` actually picked.

    Returned as a name an operator can act on, so the doctor does not have to
    re-derive the precedence rules and risk describing them differently from
    how they are implemented.
    """
    active = ca_bundle()
    if active is None:
        return "system"
    for var in CA_BUNDLE_VARS:
        if os.environ.get(var, "").strip() == active:
            return var
    return "certifi"


def ignored_ca_bundle_vars() -> list[str]:
    """Variables that are set but point at a file that is not there.

    These are being silently ignored by `ca_bundle()`. Someone who set one to
    fix a verification error deserves to be told it had no effect.
    """
    return [var for var in CA_BUNDLE_VARS
            if os.environ.get(var, "").strip()
            and not Path(os.environ[var].strip()).is_file()]


def ssl_context() -> ssl.SSLContext:
    """A verifying TLS context, shared by every network call ColdLight makes.

    Certificate and hostname checks stay enabled, and nothing in ColdLight may
    turn them off. Memoised: building a context parses the whole bundle, and
    a scan can make hundreds of requests.
    """
    global _ssl_ctx
    if _ssl_ctx is None:
        context = ssl.create_default_context(cafile=ca_bundle())
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        _ssl_ctx = context
    return _ssl_ctx


def reset() -> None:
    """Drop the memoised context.

    Only for tests that change the CA environment: without this, such a test
    is answered by a context whichever test ran first already built.
    """
    global _ssl_ctx
    _ssl_ctx = None
