#!/usr/bin/env python3
"""
ColdLight scope and authorization guard.

Everything else in ColdLight reads: source files, manifests, public advisory
databases, DNS. Nothing it does reaches into a system under assessment.
Active probing breaks that -- it sends traffic to a host someone owns -- so it
does not get to run on a flag. It runs against a declared, time-bounded,
signed-off scope, or it does not run.

THE RULE THIS MODULE EXISTS TO ENFORCE: deny by default. No scope file means
nothing active happens. An empty target list means nothing active happens. A
target nobody listed means nothing active happens. "I forgot to configure it"
must never be the same thing as "everything is permitted".

Four properties keep it honest rather than decorative:

  1. Exclusions always win. A host in `excluded` cannot be pulled back into
     scope by a wildcard in `targets`, in either order. Carve-outs are the
     whole reason a scope document has exclusions, and a precedence rule that
     let the broad pattern win would silently void them.
  2. Wildcards are bounded. `*` and `*.com` are refused at load time. A scope
     file that authorises most of the internet is a configuration mistake, not
     an authorization, and the time to say so is before anyone runs anything.
  3. It is time-bounded. Authorization expires. A run outside the window is
     refused with the dates, not warned about.
  4. Every decision is recorded. The audit trail is the point: afterwards you
     can show precisely which targets were allowed, which were refused, and
     under what reference -- including the refusals, which are the interesting
     half if anyone asks what you touched.

Stdlib only. This module makes no network calls of its own; it only answers
whether one is permitted.
"""

from __future__ import annotations

import datetime
import fnmatch
import ipaddress
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

__all__ = [
    "ScopeError", "ScopeDenied", "ScopeRule", "Decision", "Scope",
    "load_scope", "parse_rule", "TEMPLATE",
]

PLACEHOLDER_MARKERS = ("CHANGE-ME", "TODO", "XXX", "FIXME")

ALLOWED_SCHEMES = ("http", "https")

# A wildcard must leave at least this many fixed labels, so "*.example.com"
# is usable and "*.com" is not.
_MIN_WILDCARD_LABELS = 2

# Multi-label public suffixes, so "*.co.uk" is refused for the same reason
# "*.com" is. This is deliberately a short list, not the Public Suffix List --
# it catches the common mistakes, and the bounded-wildcard rule below does the
# rest. Documented as partial rather than presented as complete.
_PUBLIC_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.nz", "co.jp", "co.za", "com.br", "com.cn", "com.mx", "co.in",
    "com.tr", "com.sg", "com.hk", "co.kr", "github.io", "herokuapp.com",
    "azurewebsites.net", "cloudfront.net", "amazonaws.com", "vercel.app",
    "netlify.app", "pages.dev", "workers.dev", "firebaseapp.com",
})

TEMPLATE = '''\
# ColdLight scope and authorization.
#
#   coldlight scope check scope.toml                # validate and show the scope
#   coldlight scope check scope.toml --target URL   # ask about one target
#
# Nothing active runs without this file. Deny by default: a target that is not
# listed here is refused, and anything in `excluded` stays refused even if a
# wildcard in `targets` would otherwise cover it.

[scope]
# The ticket / rules-of-engagement document this work runs under. Required,
# and a CHANGE-ME value is refused.
authorization_reference = "CHANGE-ME-TICKET"

# Who signed it off. Recorded in the report.
authorized_by = "CHANGE-ME (name, role)"

# Authorization expires. Outside this window every target is refused.
valid_from  = "2026-11-18"
valid_until = "2026-12-02"

# What may be probed. A bare host allows any port and any path on it; add a
# path to narrow it to that subtree. "*.dev.example.com" covers subdomains
# only -- list the apex separately if you mean it too.
targets = [
  "https://staging.corp.example.com/api/chat",
  "http://localhost:8000",
]

# Carve-outs. These always win, whatever `targets` says.
excluded = [
  "https://staging.corp.example.com/api/admin",
  "*.prod.corp.example.com",
]

# --- optional: the endpoint `coldlight probe` sends benign canaries to ---------
#
# [probe]
# url = "https://staging.corp.example.com/api/chat"
# method = "POST"
# # {{PROMPT}} is replaced with the canary text, escaped for a JSON string.
# body = '{"message": "{{PROMPT}}"}'
# # Dot path to the model's reply in the JSON response; "" means raw body.
# response_path = "reply"
# # Headers are sent as given and REDACTED in all output.
# [probe.headers]
# "Content-Type" = "application/json"
# # "Authorization" = "Bearer ..."
'''


class ScopeError(ValueError):
    """The scope file is missing, malformed, or authorises too much."""


class ScopeDenied(PermissionError):
    """A target is not authorised. Carries the decision that refused it."""

    def __init__(self, decision: "Decision"):
        super().__init__(decision.reason)
        self.decision = decision


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ScopeRule:
    raw: str
    host: str                 # lowercased; may contain a leading "*."
    scheme: str = ""          # "" = any allowed scheme
    port: int | None = None   # None = any port
    path: str = ""            # "" = any path

    @property
    def wildcard(self) -> bool:
        return self.host.startswith("*.")

    def matches(self, scheme: str, host: str, port: int | None,
                path: str) -> bool:
        if self.scheme and self.scheme != scheme:
            return False
        if self.port is not None and self.port != port:
            return False
        if not self._host_matches(host):
            return False
        return self._path_matches(path)

    def _host_matches(self, host: str) -> bool:
        host = (host or "").lower().rstrip(".")
        if self.wildcard:
            # "*.example.com" means subdomains, not the apex. Someone who
            # means both lists both; inferring it would quietly widen scope.
            return (fnmatch.fnmatch(host, self.host)
                    and host != self.host[2:])
        return host == self.host

    def _path_matches(self, path: str) -> bool:
        if not self.path:
            return True
        candidate = path or "/"
        base = self.path.rstrip("/") or "/"
        if candidate == base:
            return True
        # A path rule covers its subtree, but only at a separator boundary:
        # /api must not match /apikeys.
        prefix = base if base.endswith("/") else base + "/"
        return candidate.startswith(prefix)

    def describe(self) -> str:
        return self.raw


def _reject(raw: str, why: str) -> None:
    raise ScopeError(f"scope entry {raw!r}: {why}")


def parse_rule(raw: str) -> ScopeRule:
    """Parse one scope entry, refusing anything over-broad.

    Accepts a bare host, a host glob, or a URL. Refuses bare wildcards,
    wildcards over a public suffix, and CIDR blocks.
    """
    text = (raw or "").strip()
    if not text:
        _reject(raw, "empty entry")

    # CIDR, checked against the raw text before parsing: a whole network is
    # too much authority for a tool whose only active capability is sending
    # requests to one HTTP endpoint.
    if re.fullmatch(r"(?:https?://)?[0-9.]+/\d{1,2}", text):
        _reject(raw, "CIDR blocks are not accepted; list hosts individually")

    scheme = ""
    if "://" in text:
        parts = urlsplit(text)
        scheme = parts.scheme.lower()
        if scheme not in ALLOWED_SCHEMES:
            _reject(raw, f"scheme {scheme!r} is not probeable "
                         f"(expected http or https)")
    else:
        parts = urlsplit("//" + text)

    if parts.query or parts.fragment:
        _reject(raw, "query strings and fragments are not part of a scope "
                     "entry; list the path instead")

    try:
        port = parts.port
    except ValueError:
        _reject(raw, "port is not a number")
        raise  # unreachable; keeps the type checker honest

    host = (parts.hostname or "").lower().rstrip(".")
    path = parts.path or ""
    if not host:
        _reject(raw, "no host")

    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    if "*" in host:
        if is_ip:
            _reject(raw, "wildcards are not valid in an IP address")
        if not host.startswith("*."):
            _reject(raw, "a wildcard is only allowed as a leading '*.' label")
        if "*" in host[2:]:
            _reject(raw, "only one leading wildcard label is allowed")
        remainder = host[2:]
        labels = [label for label in remainder.split(".") if label]
        if len(labels) < _MIN_WILDCARD_LABELS:
            _reject(raw, f"wildcard is too broad: {host!r} would cover an "
                         f"entire top-level domain")
        if remainder in _PUBLIC_SUFFIXES:
            _reject(raw, f"wildcard is too broad: {remainder!r} is a public "
                         f"suffix, so {host!r} would cover unrelated parties")
        if all(label.isdigit() for label in labels):
            # "*.0.0.1" is a DNS wildcard that can never match anything. It
            # usually means someone wanted an address range, so say so rather
            # than accept a rule that silently matches nothing.
            _reject(raw, "wildcards do not apply to IP addresses; list the "
                         "hosts individually")

    if path in ("/", ""):
        path = ""

    return ScopeRule(raw=text if "://" in text else host + path,
                     host=host, scheme=scheme, port=port, path=path)


# ---------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------

@dataclass
class Decision:
    target: str
    allowed: bool
    reason: str
    rule: str = ""
    authorization_reference: str = ""
    at: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    def __str__(self) -> str:
        verdict = "ALLOWED" if self.allowed else "REFUSED"
        suffix = f" (rule: {self.rule})" if self.rule else ""
        return f"{verdict}  {self.target}  -- {self.reason}{suffix}"


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------

@dataclass
class Scope:
    authorization_reference: str = ""
    authorized_by: str = ""
    valid_from: datetime.date | None = None
    valid_until: datetime.date | None = None
    targets: list[ScopeRule] = field(default_factory=list)
    excluded: list[ScopeRule] = field(default_factory=list)
    source: str = ""
    probe: dict = field(default_factory=dict)
    decisions: list[Decision] = field(default_factory=list)

    # -- window ----------------------------------------------------------
    def window_error(self, now: datetime.datetime | None = None) -> str:
        """Why the authorization window forbids acting now, or ""."""
        today = (now or _now()).date()
        if self.valid_from and today < self.valid_from:
            return (f"authorization does not start until "
                    f"{self.valid_from.isoformat()} (today is "
                    f"{today.isoformat()})")
        if self.valid_until and today > self.valid_until:
            return (f"authorization expired on "
                    f"{self.valid_until.isoformat()} (today is "
                    f"{today.isoformat()})")
        return ""

    @property
    def is_empty(self) -> bool:
        return not self.targets

    # -- the gate --------------------------------------------------------
    def check(self, target: str,
              now: datetime.datetime | None = None) -> Decision:
        """Decide whether `target` may be probed. Records the decision."""
        decision = self._decide(target, now)
        self.decisions.append(decision)
        return decision

    def require(self, target: str,
                now: datetime.datetime | None = None) -> Decision:
        """Like check(), but raise ScopeDenied when refused."""
        decision = self.check(target, now)
        if not decision.allowed:
            raise ScopeDenied(decision)
        return decision

    def _decide(self, target: str,
                now: datetime.datetime | None) -> Decision:
        stamp = (now or _now()).isoformat()

        def refuse(reason: str, rule: str = "") -> Decision:
            return Decision(target=target, allowed=False, reason=reason,
                            rule=rule, at=stamp,
                            authorization_reference=(
                                self.authorization_reference))

        if self.is_empty:
            return refuse("no targets are declared in scope, so nothing is "
                          "authorised (deny by default)")

        window = self.window_error(now)
        if window:
            return refuse(window)

        try:
            scheme, host, port, path = _split_target(target)
        except ScopeError as exc:
            return refuse(str(exc))

        # Exclusions first, and they are final: a carve-out that a wildcard
        # could override would not be a carve-out.
        for rule in self.excluded:
            if rule.matches(scheme, host, port, path):
                return refuse("explicitly excluded from scope",
                              rule.describe())

        for rule in self.targets:
            if rule.matches(scheme, host, port, path):
                return Decision(
                    target=target, allowed=True,
                    reason=f"in scope under {self.authorization_reference}",
                    rule=rule.describe(), at=stamp,
                    authorization_reference=self.authorization_reference)

        return refuse("not listed in scope (deny by default)")

    # -- serialisation ---------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "authorization_reference": self.authorization_reference,
            "authorized_by": self.authorized_by,
            "valid_from": self.valid_from.isoformat() if self.valid_from
                          else "",
            "valid_until": self.valid_until.isoformat() if self.valid_until
                           else "",
            "targets": [r.describe() for r in self.targets],
            "excluded": [r.describe() for r in self.excluded],
            "decisions": [d.to_dict() for d in self.decisions],
        }

    def summary(self) -> str:
        lines = [
            "Scope and authorization",
            "=" * 60,
            f"source        : {self.source or '(none)'}",
            f"authorization : {self.authorization_reference}",
            f"authorized by : {self.authorized_by or '(not recorded)'}",
        ]
        window = "unbounded"
        if self.valid_from or self.valid_until:
            window = (f"{self.valid_from or 'any'} .. "
                      f"{self.valid_until or 'any'}")
        lines.append(f"valid         : {window}")
        problem = self.window_error()
        if problem:
            lines.append(f"  !! {problem}")
        lines.append("")
        lines.append(f"in scope ({len(self.targets)}):")
        for rule in self.targets:
            lines.append(f"  + {rule.describe()}")
        if self.excluded:
            lines.append(f"excluded ({len(self.excluded)}) "
                         f"-- these always win:")
            for rule in self.excluded:
                lines.append(f"  - {rule.describe()}")
        if self.probe:
            lines.append("")
            lines.append(f"probe endpoint: {self.probe.get('url', '(none)')}")
        lines.append("")
        lines.append("Anything not listed above is refused.")
        return "\n".join(lines)


def _split_target(target: str) -> tuple[str, str, int | None, str]:
    text = (target or "").strip()
    if not text:
        raise ScopeError("empty target")
    if "://" not in text:
        text = "https://" + text
    parts = urlsplit(text)
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise ScopeError(f"scheme {scheme!r} is not probeable")
    try:
        port = parts.port
    except ValueError:
        raise ScopeError("target port is not a number") from None
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise ScopeError("target has no host")
    return scheme, host, port, parts.path or ""


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def _is_placeholder(value: str) -> bool:
    return (not value) or any(m in value.upper()
                              for m in PLACEHOLDER_MARKERS)


def _as_date(value, label: str) -> datetime.date | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime.datetime):
        return value.date()
    if isinstance(value, datetime.date):
        return value
    try:
        return datetime.date.fromisoformat(str(value))
    except ValueError:
        raise ScopeError(f"{label} is not an ISO date (YYYY-MM-DD): "
                         f"{value!r}") from None


def _as_list(value, label: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if not isinstance(value, (list, tuple)):
        raise ScopeError(f"{label} must be a list of strings")
    return [str(v) for v in value]


def load_scope(path: str | Path) -> Scope:
    """Load and validate a scope file. Raises ScopeError if unusable."""
    import tomllib

    file_path = Path(path)
    if not file_path.is_file():
        raise ScopeError(
            f"no scope file at {file_path}. Active probing requires one -- "
            f"write a template with `coldlight scope --init {file_path}`."
        )
    try:
        data = tomllib.loads(file_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - tomllib raises its own type
        raise ScopeError(f"{file_path} is not valid TOML: {exc}") from exc

    section = data.get("scope") or {}
    if not isinstance(section, dict):
        raise ScopeError("[scope] must be a table")

    reference = str(section.get("authorization_reference", "") or "")
    if _is_placeholder(reference):
        raise ScopeError(
            "scope.authorization_reference is empty or still a placeholder. "
            "Active probing has to be traceable to a real authorization, so "
            "this is refused rather than warned about."
        )

    valid_from = _as_date(section.get("valid_from"), "scope.valid_from")
    valid_until = _as_date(section.get("valid_until"), "scope.valid_until")
    if valid_from and valid_until and valid_until < valid_from:
        raise ScopeError(
            f"scope.valid_until ({valid_until}) is before scope.valid_from "
            f"({valid_from})"
        )

    targets, excluded = [], []
    for raw in _as_list(section.get("targets"), "scope.targets"):
        targets.append(parse_rule(raw))
    for raw in _as_list(section.get("excluded"), "scope.excluded"):
        excluded.append(parse_rule(raw))

    probe = data.get("probe") or {}
    if not isinstance(probe, dict):
        raise ScopeError("[probe] must be a table")

    return Scope(
        authorization_reference=reference,
        authorized_by=str(section.get("authorized_by", "") or ""),
        valid_from=valid_from,
        valid_until=valid_until,
        targets=targets,
        excluded=excluded,
        source=str(file_path),
        probe=dict(probe),
    )


def write_template(path: str | Path) -> str:
    """Write a commented scope template. Refuses to overwrite."""
    file_path = Path(path)
    if file_path.exists():
        raise ScopeError(f"{file_path} already exists; not overwriting a "
                         f"scope file")
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(TEMPLATE, encoding="utf-8")
    return str(file_path)
