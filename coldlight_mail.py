#!/usr/bin/env python3
"""
ColdLight email authentication posture audit: can an attacker send mail that
appears to come from this domain?

This is the technical counterpart to the phishing/awareness half of ColdLight. A
click-rate tells you people are human. This tells you whether a real attacker
could put YOUR domain in the From: line, which turns "31% clicked" from a
finding about people into a finding about a control you can fix this week.

THE MISCONCEPTION THIS EXISTS TO CORRECT: SPF does not stop spoofing of the
visible From: header. SPF authenticates the SMTP envelope sender
(MAIL FROM / Return-Path), which users never see. A domain can publish a
flawless `v=spf1 ... -all` and still be trivially spoofable in the only field
the recipient reads. Only DMARC requires alignment with the visible From:,
so DMARC policy is what actually decides spoofability.

Checks: SPF (incl. the 10-DNS-lookup limit that silently breaks records),
DMARC (policy, subdomain policy, enforcement percentage, reporting), DKIM
(common selectors, key strength), MTA-STS, TLS-RPT and DNSSEC.

PASSIVE: this reads public DNS over DNS-over-HTTPS. The only request that
touches the target's own infrastructure is the well-known MTA-STS policy file
over HTTPS, which `--no-fetch` disables. Nothing is sent, probed or exploited.

Stdlib only.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field

from coldlight_trust import ssl_context

USER_AGENT = "ColdLight-MailAudit/1.0"

# Public DNS-over-HTTPS resolvers, tried in order.
DOH_RESOLVERS = (
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
)

DNS_TIMEOUT = 15
HTTP_TIMEOUT = 15

TXT, MX, CNAME = 16, 15, 5

# RFC 7208 section 4.6.4: more than 10 DNS-querying mechanisms is a permerror,
# which makes SPF evaluation fail -- usually open rather than closed.
SPF_LOOKUP_LIMIT = 10
SPF_QUERY_BUDGET = 25          # our own cap on recursive expansion

SEVERITY_ORDER = {
    "CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "OK": 0,
}

# Selectors used by the major providers. DKIM selectors are arbitrary, so this
# is a probe, never an inventory -- see DkimResult.conclusive.
COMMON_SELECTORS = (
    "google", "selector1", "selector2", "k1", "k2", "k3", "s1", "s2",
    "dkim", "default", "mail", "smtp", "mx", "zoho", "protonmail",
    "protonmail2", "protonmail3", "sendgrid", "mandrill", "mailjet",
    "mailgun", "mg", "amazonses", "hs1", "hs2", "ctct1", "ctct2",
    "everlytickey1", "sig1", "litesrv", "pm", "fd", "fd2", "scph0",
    "dkim1024", "20230601", "20161025",
)


class MailAuditError(RuntimeError):
    """DNS could not be reached at all."""


# ---------------------------------------------------------------------------
# DNS over HTTPS
# ---------------------------------------------------------------------------

@dataclass
class DnsAnswer:
    status: int = 0            # 0 NOERROR, 3 NXDOMAIN
    authenticated: bool = False  # the resolver's DNSSEC AD flag
    records: list[str] = field(default_factory=list)

    @property
    def exists(self) -> bool:
        return self.status == 0 and bool(self.records)


_QUOTED_CHUNK = re.compile(r'"((?:[^"\\]|\\.)*)"')


def unquote_txt(data: str) -> str:
    """Join a TXT record's quoted chunks.

    DNS TXT strings cap at 255 bytes, so long records (SPF with many includes,
    DKIM public keys) arrive as `"part one" "part two"` and MUST be
    concatenated with no separator. Splitting a DKIM key here would silently
    corrupt it.
    """
    chunks = _QUOTED_CHUNK.findall(data or "")
    if chunks:
        return "".join(c.replace('\\"', '"') for c in chunks)
    return (data or "").strip()


def doh_query(name: str, rtype: str = "TXT", *,
              resolvers=DOH_RESOLVERS) -> DnsAnswer:
    """Resolve `name` over DNS-over-HTTPS, trying each resolver in turn."""
    params = urllib.parse.urlencode({"name": name, "type": rtype})
    last_error: Exception | None = None

    for base in resolvers:
        request = urllib.request.Request(
            f"{base}?{params}",
            headers={"Accept": "application/dns-json", "User-Agent": USER_AGENT},
        )
        try:
            with urllib.request.urlopen(request, timeout=DNS_TIMEOUT,
                                        context=ssl_context()) as response:
                payload = json.loads(response.read().decode("utf-8", "replace"))
        except (urllib.error.URLError, ValueError, OSError) as exc:
            last_error = exc
            continue

        wanted = {"TXT": TXT, "MX": MX}.get(rtype.upper(), 0)
        records = [
            unquote_txt(entry.get("data", ""))
            for entry in payload.get("Answer", []) or []
            if not wanted or entry.get("type") == wanted
        ]
        return DnsAnswer(
            status=int(payload.get("Status", 0) or 0),
            authenticated=bool(payload.get("AD", False)),
            records=[r for r in records if r],
        )

    raise MailAuditError(
        f"could not reach any DNS-over-HTTPS resolver: {last_error}"
    )


# ---------------------------------------------------------------------------
# SPF
# ---------------------------------------------------------------------------

# Mechanisms that cost a DNS lookup against the limit of 10.
_SPF_LOOKUP_MECHANISMS = ("include", "a", "mx", "ptr", "exists", "redirect")


@dataclass
class SpfResult:
    present: bool = False
    raw: str = ""
    all_qualifier: str = ""        # '-', '~', '?', '+' or '' when absent
    includes: list[str] = field(default_factory=list)
    lookups: int = 0
    lookup_truncated: bool = False
    has_ptr: bool = False
    multiple_records: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def all_meaning(self) -> str:
        return {
            "-": "fail (hard) -- correct",
            "~": "softfail -- tolerated, prefer -all",
            "?": "neutral -- no assertion, as weak as having nothing",
            "+": "pass -- ANY host may send as this domain",
            "": "no 'all' mechanism -- defaults to neutral",
        }.get(self.all_qualifier, "unknown")


def parse_spf(record: str) -> tuple[str, list[str], bool, list[str]]:
    """Return (all_qualifier, includes, has_ptr, lookup_mechanisms)."""
    all_qualifier = ""
    includes: list[str] = []
    has_ptr = False
    lookup_mechanisms: list[str] = []

    for term in (record or "").split()[1:]:       # skip the v=spf1 version
        bare = term.lstrip("+-~?")
        qualifier = term[0] if term and term[0] in "+-~?" else "+"
        lowered = bare.lower()

        if lowered == "all":
            all_qualifier = qualifier
            continue
        if lowered.startswith("include:"):
            includes.append(bare.split(":", 1)[1])
            lookup_mechanisms.append(term)
            continue
        if lowered.startswith("redirect="):
            lookup_mechanisms.append(term)
            continue
        if lowered == "ptr" or lowered.startswith("ptr:"):
            has_ptr = True
            lookup_mechanisms.append(term)
            continue
        if lowered.split(":", 1)[0].split("=", 1)[0] in _SPF_LOOKUP_MECHANISMS:
            lookup_mechanisms.append(term)

    return all_qualifier, includes, has_ptr, lookup_mechanisms


def _spf_record_for(domain: str, query) -> tuple[str, bool, list[str]]:
    """Fetch the SPF record for a domain. Returns (record, multiple, errors)."""
    errors: list[str] = []
    answer = query(domain, "TXT")
    candidates = [r for r in answer.records if r.lower().startswith("v=spf1")]

    if not candidates:
        return "", False, errors
    if len(candidates) > 1:
        errors.append(
            f"{domain} publishes {len(candidates)} SPF records; RFC 7208 "
            f"requires exactly one -- this is a permerror and SPF will not "
            f"evaluate"
        )
        return candidates[0], True, errors
    return candidates[0], False, errors


def count_spf_lookups(domain: str, query, *,
                      budget: int = SPF_QUERY_BUDGET) -> tuple[int, bool, list[str]]:
    """Count DNS-querying mechanisms across the whole SPF evaluation.

    The limit applies to the full recursive expansion, not just the top-level
    record, so a record that looks short can still blow the limit through its
    includes. Returns (count, truncated, errors).
    """
    seen: set[str] = set()
    errors: list[str] = []
    spent = 0
    total = 0
    truncated = False

    def walk(name: str, depth: int) -> None:
        nonlocal spent, total, truncated
        if depth > 10 or name.lower() in seen:
            return
        seen.add(name.lower())
        if spent >= budget:
            truncated = True
            return

        spent += 1
        record, _multiple, record_errors = _spf_record_for(name, query)
        errors.extend(record_errors)
        if not record:
            return

        _all, includes, _ptr, mechanisms = parse_spf(record)
        total += len(mechanisms)
        for target in includes:
            walk(target, depth + 1)

    walk(domain, 0)
    return total, truncated, errors


def check_spf(domain: str, query) -> SpfResult:
    result = SpfResult()
    record, multiple, errors = _spf_record_for(domain, query)
    result.errors.extend(errors)
    result.multiple_records = multiple

    if not record:
        return result

    result.present = True
    result.raw = record
    (result.all_qualifier, result.includes,
     result.has_ptr, _mechanisms) = parse_spf(record)

    lookups, truncated, lookup_errors = count_spf_lookups(domain, query)
    result.lookups = lookups
    result.lookup_truncated = truncated
    for error in lookup_errors:
        if error not in result.errors:
            result.errors.append(error)

    return result


# ---------------------------------------------------------------------------
# DMARC
# ---------------------------------------------------------------------------

@dataclass
class DmarcResult:
    present: bool = False
    raw: str = ""
    policy: str = ""            # none | quarantine | reject
    subdomain_policy: str = ""  # sp=, falls back to policy
    percent: int = 100
    rua: list[str] = field(default_factory=list)
    ruf: list[str] = field(default_factory=list)
    adkim: str = "r"
    aspf: str = "r"
    multiple_records: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def effective_subdomain_policy(self) -> str:
        return self.subdomain_policy or self.policy

    @property
    def enforcing(self) -> bool:
        return self.policy in ("quarantine", "reject")


def parse_dmarc(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in (record or "").split(";"):
        if "=" not in part:
            continue
        key, _, value = part.partition("=")
        tags[key.strip().lower()] = value.strip()
    return tags


def check_dmarc(domain: str, query) -> DmarcResult:
    result = DmarcResult()
    answer = query(f"_dmarc.{domain}", "TXT")
    candidates = [r for r in answer.records if r.lower().startswith("v=dmarc1")]

    if not candidates:
        return result
    if len(candidates) > 1:
        result.multiple_records = True
        result.errors.append(
            f"_dmarc.{domain} publishes {len(candidates)} DMARC records; "
            f"receivers must ignore all of them, so the domain behaves as if "
            f"it had no DMARC at all"
        )

    result.present = True
    result.raw = candidates[0]
    tags = parse_dmarc(candidates[0])

    result.policy = (tags.get("p", "") or "").lower()
    result.subdomain_policy = (tags.get("sp", "") or "").lower()
    result.adkim = (tags.get("adkim", "r") or "r").lower()
    result.aspf = (tags.get("aspf", "r") or "r").lower()

    try:
        result.percent = max(0, min(100, int(tags.get("pct", "100"))))
    except ValueError:
        result.percent = 100
        result.errors.append("pct= is not a number; receivers will assume 100")

    for tag, target in (("rua", result.rua), ("ruf", result.ruf)):
        raw = tags.get(tag, "")
        target.extend(a.strip() for a in raw.split(",") if a.strip())

    if result.policy not in ("none", "quarantine", "reject"):
        result.errors.append(
            f"p={result.policy or '(missing)'!r} is not valid; a DMARC record "
            f"without a usable policy is ignored by receivers"
        )

    return result


# ---------------------------------------------------------------------------
# DKIM
# ---------------------------------------------------------------------------

@dataclass
class DkimKey:
    selector: str
    raw: str = ""
    key_type: str = "rsa"
    bits: int | None = None
    testing: bool = False
    revoked: bool = False       # p= present but empty means "revoked"


@dataclass
class DkimResult:
    keys: list[DkimKey] = field(default_factory=list)
    selectors_probed: int = 0
    # True when *._domainkey.<domain> answers for any name. Without detecting
    # this, every probed selector appears to "exist" and the result is noise.
    wildcard: bool = False

    @property
    def found(self) -> bool:
        return bool(self.keys)

    @property
    def conclusive(self) -> bool:
        """Finding nothing proves nothing.

        DKIM selectors are arbitrary strings chosen by the sender, so they
        cannot be enumerated from DNS. A negative probe result means "none of
        the common selectors resolved", NOT "DKIM is not configured".
        """
        return self.found


def _der_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Read one DER tag-length-value. Returns (tag, value, next_offset)."""
    if offset + 2 > len(data):
        raise ValueError("truncated DER")
    tag = data[offset]
    length = data[offset + 1]
    offset += 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or offset + count > len(data):
            raise ValueError("bad DER length")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    if offset + length > len(data):
        raise ValueError("DER value overruns buffer")
    return tag, data[offset:offset + length], offset + length


def rsa_key_bits(der: bytes) -> int | None:
    """Modulus size of an RSA SubjectPublicKeyInfo, in bits.

    Walks the DER rather than guessing from the base64 length -- reporting a
    wrong key size in a security report is worse than reporting none.
    """
    try:
        _tag, spki, _ = _der_tlv(der, 0)              # outer SEQUENCE
        _tag, _algorithm, offset = _der_tlv(spki, 0)  # AlgorithmIdentifier
        tag, bitstring, _ = _der_tlv(spki, offset)    # BIT STRING
        if tag != 0x03 or not bitstring:
            return None
        _tag, rsa_key, _ = _der_tlv(bitstring[1:], 0)  # skip unused-bits byte
        tag, modulus, _ = _der_tlv(rsa_key, 0)         # INTEGER modulus
        if tag != 0x02:
            return None
        trimmed = modulus.lstrip(b"\x00")
        return len(trimmed) * 8 if trimmed else None
    except (ValueError, IndexError):
        return None


def parse_dkim(selector: str, record: str) -> DkimKey:
    key = DkimKey(selector=selector, raw=record)
    tags = parse_dmarc(record)        # same tag=value; syntax

    key.key_type = (tags.get("k", "rsa") or "rsa").lower()
    flags = (tags.get("t", "") or "").lower()
    key.testing = "y" in flags.split(":")

    public = tags.get("p", None)
    if public is not None and not public.strip():
        key.revoked = True
        return key
    if not public:
        return key

    try:
        der = base64.b64decode(public + "=" * (-len(public) % 4), validate=False)
    except Exception:  # noqa: BLE001 - malformed key material
        return key

    if key.key_type == "ed25519":
        key.bits = len(der) * 8          # 32 bytes -> 256
    else:
        key.bits = rsa_key_bits(der)
    return key


def check_dkim(domain: str, query, *, selectors=COMMON_SELECTORS,
               workers: int = 8) -> DkimResult:
    result = DkimResult(selectors_probed=len(selectors))

    def probe(selector: str) -> DkimKey | None:
        answer = query(f"{selector}._domainkey.{domain}", "TXT")
        for record in answer.records:
            if "p=" in record and (
                record.lower().startswith("v=dkim1") or "k=" in record.lower()
            ):
                return parse_dkim(selector, record)
        return None

    # Control probe: a name nobody would ever configure. If it answers, the
    # zone has a wildcard under _domainkey and per-selector results are
    # meaningless -- reporting 30 "found" selectors would be pure noise.
    control = probe(f"coldlight-control-{secrets.token_hex(5)}")
    if control is not None:
        result.wildcard = True
        control.selector = "*"
        result.keys = [control]
        return result

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for key in pool.map(probe, selectors):
            if key is not None:
                result.keys.append(key)

    result.keys.sort(key=lambda k: k.selector)
    return result


# ---------------------------------------------------------------------------
# MTA-STS, TLS-RPT, DNSSEC, MX
# ---------------------------------------------------------------------------

@dataclass
class MtaStsResult:
    dns_present: bool = False
    policy_id: str = ""
    fetch_attempted: bool = False
    policy_fetched: bool = False
    mode: str = ""              # enforce | testing | none
    max_age: int = 0
    mx_patterns: list[str] = field(default_factory=list)
    fetch_error: str = ""


def check_mta_sts(domain: str, query, *, fetch: bool = True) -> MtaStsResult:
    result = MtaStsResult()
    answer = query(f"_mta-sts.{domain}", "TXT")
    records = [r for r in answer.records if r.lower().startswith("v=stsv1")]
    if not records:
        return result

    result.dns_present = True
    result.policy_id = parse_dmarc(records[0]).get("id", "")

    if not fetch:
        return result

    result.fetch_attempted = True
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT,
                                    context=ssl_context()) as response:
            body = response.read(64 * 1024).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as exc:
        result.fetch_error = str(getattr(exc, "reason", exc))
        return result

    result.policy_fetched = True
    for line in body.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "mode":
            result.mode = value.lower()
        elif key == "max_age":
            try:
                result.max_age = int(value)
            except ValueError:
                pass
        elif key == "mx":
            result.mx_patterns.append(value)
    return result


def check_tls_rpt(domain: str, query) -> str:
    answer = query(f"_smtp._tls.{domain}", "TXT")
    for record in answer.records:
        if record.lower().startswith("v=tlsrptv1"):
            return record
    return ""


# ---------------------------------------------------------------------------
# Findings and verdict
# ---------------------------------------------------------------------------

# Severities here are our assessment of email-authentication posture -- no
# external authority rates "DMARC p=none" as HIGH. Checked against
# coldlight_vulnintel.SEVERITY_SOURCES by a test.
SEVERITY_SOURCE = "coldlight-judgement"


@dataclass
class MailFinding:
    check: str
    severity: str
    title: str
    detail: str = ""
    remediation: str = ""
    severity_source: str = SEVERITY_SOURCE

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class MailAudit:
    domain: str
    spf: SpfResult = field(default_factory=SpfResult)
    dmarc: DmarcResult = field(default_factory=DmarcResult)
    dkim: DkimResult = field(default_factory=DkimResult)
    mta_sts: MtaStsResult = field(default_factory=MtaStsResult)
    tls_rpt: str = ""
    dnssec: bool = False
    mx: list[str] = field(default_factory=list)
    findings: list[MailFinding] = field(default_factory=list)

    @property
    def spoofable(self) -> bool:
        """Would a forged `From: @domain` be ACCEPTED by receivers?

        Decided by DMARC alone: it is the only mechanism that constrains the
        header the recipient actually sees.

        Only `p=reject` at 100% makes this false. `p=quarantine` deliberately
        counts as spoofable: the forgery is still accepted and filed to spam
        rather than refused, recipients do read spam, and the DMARC spec
        leaves quarantine handling to the receiver -- some mark as spam, some
        deliver with a warning. For a security finding, err conservative.
        `protection_level` carries the three-way nuance.
        """
        if not self.dmarc.present or self.dmarc.policy != "reject":
            return True
        return self.dmarc.percent < 100

    @property
    def protection_level(self) -> str:
        """'none', 'partial' or 'full' -- so a bool can't over-reassure."""
        if not self.dmarc.present or self.dmarc.policy == "none":
            return "none"
        if self.dmarc.policy == "reject" and self.dmarc.percent >= 100:
            return "full"
        return "partial"

    @property
    def null_mx(self) -> bool:
        """RFC 7505 null MX ('0 .') -- the domain declares it accepts no mail.

        This is good practice for a non-mail domain, and it means inbound
        transport hardening (MTA-STS, TLS-RPT) does not apply.
        """
        return bool(self.mx) and all(
            record.split()[-1] == "." for record in self.mx
        )

    @property
    def receives_mail(self) -> bool:
        return bool(self.mx) and not self.null_mx

    @property
    def subdomains_spoofable(self) -> bool:
        policy = self.dmarc.effective_subdomain_policy
        return not self.dmarc.present or policy in ("", "none")

    @property
    def verdict(self) -> str:
        if not self.dmarc.present:
            return ("SPOOFABLE -- no DMARC record, so receivers have no policy "
                    "to apply to forged mail")
        if self.dmarc.policy == "none":
            return ("SPOOFABLE -- DMARC is p=none (monitor only); forged mail "
                    "is reported but still delivered")
        if self.dmarc.percent < 100:
            return (f"PARTIALLY PROTECTED -- p={self.dmarc.policy} applies to "
                    f"only {self.dmarc.percent}% of mail")
        if self.dmarc.policy == "quarantine":
            return ("PARTIALLY PROTECTED -- p=quarantine sends forgeries to "
                    "spam rather than rejecting them")
        return "PROTECTED -- p=reject at 100%; forged mail is rejected"

    def worst_severity(self) -> str:
        if not self.findings:
            return "OK"
        return max((f.severity for f in self.findings),
                   key=lambda s: SEVERITY_ORDER.get(s, 0))

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "spoofable": self.spoofable,
            "protection_level": self.protection_level,
            "subdomains_spoofable": self.subdomains_spoofable,
            "verdict": self.verdict,
            "dnssec": self.dnssec,
            "mx": self.mx,
            "null_mx": self.null_mx,
            "receives_mail": self.receives_mail,
            "spf": asdict(self.spf),
            "dmarc": asdict(self.dmarc),
            "dkim": {
                "found": self.dkim.found,
                "wildcard": self.dkim.wildcard,
                "selectors_probed": self.dkim.selectors_probed,
                "keys": [asdict(k) for k in self.dkim.keys],
            },
            "mta_sts": asdict(self.mta_sts),
            "tls_rpt": self.tls_rpt,
            "findings": [f.to_dict() for f in self.findings],
        }


def _evaluate(audit: MailAudit) -> list[MailFinding]:
    findings: list[MailFinding] = []
    spf, dmarc = audit.spf, audit.dmarc

    # ---- DMARC: the one that decides spoofability -------------------------
    if not dmarc.present:
        findings.append(MailFinding(
            "DMARC", "HIGH", "No DMARC record",
            "Without DMARC, receivers have no instruction for mail that fails "
            "authentication, and nothing requires the visible From: to align "
            "with an authenticated domain. SPF alone does not cover it.",
            f"Publish a monitoring record first: _dmarc.{audit.domain} TXT "
            f"\"v=DMARC1; p=none; rua=mailto:dmarc@{audit.domain}\", review "
            f"the aggregate reports, then raise to quarantine and reject.",
        ))
    else:
        if dmarc.policy == "none":
            findings.append(MailFinding(
                "DMARC", "HIGH", "DMARC is p=none (monitor only)",
                "Forged mail using this domain is reported but still "
                "delivered. p=none is a staging state, not protection.",
                "Once aggregate reports show your legitimate senders pass, "
                "move to p=quarantine, then p=reject.",
            ))
        elif dmarc.policy == "quarantine":
            findings.append(MailFinding(
                "DMARC", "MEDIUM", "DMARC is p=quarantine",
                "Forgeries land in spam rather than being rejected, so they "
                "remain reachable by a determined recipient.",
                "Move to p=reject once quarantine produces no false positives.",
            ))

        if dmarc.percent < 100:
            findings.append(MailFinding(
                "DMARC", "MEDIUM", f"Policy applies to only {dmarc.percent}% of mail",
                f"pct={dmarc.percent} means receivers apply p={dmarc.policy} "
                f"to that share and treat the rest as p=none.",
                "Remove pct= (or set pct=100) to enforce on all mail.",
            ))

        if not dmarc.rua:
            findings.append(MailFinding(
                "DMARC", "MEDIUM", "No aggregate reporting address (rua=)",
                "Without aggregate reports you cannot see who is sending as "
                "your domain, which makes moving to enforcement guesswork.",
                f"Add rua=mailto:dmarc@{audit.domain} to the DMARC record.",
            ))

        if audit.subdomains_spoofable and dmarc.enforcing:
            findings.append(MailFinding(
                "DMARC", "HIGH", "Subdomains are not covered",
                f"p={dmarc.policy} protects the domain itself, but the "
                f"effective subdomain policy is "
                f"'{dmarc.effective_subdomain_policy or 'none'}', so "
                f"anything.{audit.domain} can still be spoofed -- a common "
                f"phishing choice precisely because it looks related.",
                "Add sp=reject to the DMARC record.",
            ))

        for error in dmarc.errors:
            findings.append(MailFinding(
                "DMARC", "HIGH", "Invalid DMARC record", error,
                "Fix the record syntax; receivers ignore records they cannot "
                "parse, leaving the domain unprotected.",
            ))

    # ---- SPF --------------------------------------------------------------
    if not spf.present:
        findings.append(MailFinding(
            "SPF", "HIGH", "No SPF record",
            "Nothing states which hosts may send for this domain, so "
            "envelope-sender checks cannot fail and DMARC has one fewer way "
            "to pass legitimate mail.",
            f"Publish {audit.domain} TXT \"v=spf1 include:<your provider> "
            f"-all\". For a domain that sends no mail at all, "
            f"\"v=spf1 -all\" is correct.",
        ))
    else:
        if spf.all_qualifier == "+":
            findings.append(MailFinding(
                "SPF", "CRITICAL", "SPF ends in +all",
                "This explicitly authorises every host on the internet to "
                "send mail as this domain. It is strictly worse than having "
                "no SPF record.",
                "Replace +all with -all.",
            ))
        elif spf.all_qualifier == "?":
            findings.append(MailFinding(
                "SPF", "MEDIUM", "SPF ends in ?all (neutral)",
                "A neutral result asserts nothing, so the record provides "
                "essentially no protection.",
                "Change ?all to -all.",
            ))
        elif spf.all_qualifier == "":
            findings.append(MailFinding(
                "SPF", "MEDIUM", "SPF has no 'all' mechanism",
                "Evaluation falls through to a neutral result for every host "
                "not otherwise listed.",
                "Append -all to the record.",
            ))
        elif spf.all_qualifier == "~":
            findings.append(MailFinding(
                "SPF", "LOW", "SPF ends in ~all (softfail)",
                "Acceptable alongside DMARC enforcement, but -all states the "
                "intent unambiguously.",
                "Prefer -all once you are confident the record lists every "
                "legitimate sender.",
            ))

        if spf.lookups > SPF_LOOKUP_LIMIT:
            findings.append(MailFinding(
                "SPF", "HIGH",
                f"SPF exceeds the DNS lookup limit ({spf.lookups} > "
                f"{SPF_LOOKUP_LIMIT})",
                "RFC 7208 caps DNS-querying mechanisms at 10 across the whole "
                "recursive evaluation. Over the limit receivers return "
                "permerror, which commonly fails OPEN -- so the record you "
                "believe protects you may not be evaluated at all. This is "
                "easy to miss because the top-level record can look short.",
                "Flatten or remove includes, or consolidate senders, until "
                "the total is 10 or fewer.",
            ))
        elif spf.lookups >= SPF_LOOKUP_LIMIT - 2:
            findings.append(MailFinding(
                "SPF", "MEDIUM",
                f"SPF is close to the DNS lookup limit ({spf.lookups}/"
                f"{SPF_LOOKUP_LIMIT})",
                "Your providers control their own includes, so they can push "
                "you over the limit without any change on your side.",
                "Reduce includes to leave headroom.",
            ))

        if spf.has_ptr:
            findings.append(MailFinding(
                "SPF", "LOW", "SPF uses the deprecated ptr mechanism",
                "RFC 7208 advises against ptr: it is slow and some receivers "
                "ignore it.",
                "Replace ptr with explicit ip4/ip6 or include terms.",
            ))

        for error in spf.errors:
            findings.append(MailFinding(
                "SPF", "HIGH", "Invalid SPF configuration", error,
                "Publish exactly one SPF record per domain.",
            ))

    # ---- DKIM -------------------------------------------------------------
    if audit.dkim.wildcard:
        wildcard_key = audit.dkim.keys[0]
        if wildcard_key.revoked:
            findings.append(MailFinding(
                "DKIM", "INFO", "Wildcard DKIM revocation record",
                "*._domainkey answers for every selector with an empty p=, "
                "revoking all possible selectors at once. For a domain that "
                "sends no mail this is deliberate hardening, not a problem.",
                "No action needed.",
            ))
        else:
            findings.append(MailFinding(
                "DKIM", "MEDIUM", "Wildcard DKIM record publishes a usable key",
                "*._domainkey answers for every selector with a live key, so "
                "a signature naming ANY selector verifies against it. That "
                "removes the selector's value as a scoping and rotation "
                "control.",
                "Publish keys at specific selectors and remove the wildcard.",
            ))
    elif not audit.dkim.found:
        findings.append(MailFinding(
            "DKIM", "INFO",
            f"No DKIM key found at {audit.dkim.selectors_probed} common selectors",
            "This is NOT evidence that DKIM is missing. Selectors are "
            "arbitrary strings chosen by the sender and cannot be enumerated "
            "from DNS, so a negative probe is inconclusive.",
            "Confirm your selector from a message header "
            "(DKIM-Signature: s=<selector>) and re-run with --selector.",
        ))
    else:
        for key in audit.dkim.keys:
            if key.revoked:
                findings.append(MailFinding(
                    "DKIM", "INFO", f"Selector '{key.selector}' is revoked",
                    "An empty p= tag marks the key revoked, so signatures "
                    "made with it no longer verify. This is the RFC 6376 way "
                    "to retire a selector, so it is normal after key "
                    "rotation -- only investigate if you expected this "
                    "selector to be active.",
                    "No action needed unless this selector should be signing "
                    "mail; in that case republish its public key.",
                ))
            elif key.testing:
                findings.append(MailFinding(
                    "DKIM", "LOW", f"Selector '{key.selector}' is in test mode",
                    "t=y tells receivers to treat failures as if DKIM were "
                    "not deployed.",
                    "Remove t=y once signing is verified.",
                ))
            elif key.bits and key.key_type == "rsa" and key.bits < 1024:
                findings.append(MailFinding(
                    "DKIM", "HIGH",
                    f"Selector '{key.selector}' uses a {key.bits}-bit RSA key",
                    "Below 1024 bits the signature offers no meaningful "
                    "assurance.",
                    "Rotate to a 2048-bit key.",
                ))
            elif key.bits and key.key_type == "rsa" and key.bits < 2048:
                findings.append(MailFinding(
                    "DKIM", "MEDIUM",
                    f"Selector '{key.selector}' uses a {key.bits}-bit RSA key",
                    "1024-bit RSA is below current guidance for DKIM.",
                    "Rotate to a 2048-bit key.",
                ))

    # ---- Transport hardening (inbound mail only) -------------------------
    if audit.null_mx:
        findings.append(MailFinding(
            "MX", "INFO", "Null MX: domain declares it accepts no mail",
            "An MX of '0 .' (RFC 7505) tells senders this domain receives no "
            "mail, so they fail immediately instead of queueing. Correct "
            "hardening for a non-mail domain; inbound TLS controls "
            "(MTA-STS, TLS-RPT) do not apply.",
            "No action needed.",
        ))

    if audit.receives_mail:
        if not audit.mta_sts.dns_present:
            findings.append(MailFinding(
                "MTA-STS", "LOW", "No MTA-STS policy",
                "Without MTA-STS, an active attacker can strip STARTTLS and "
                "downgrade inbound mail to plaintext.",
                f"Publish _mta-sts.{audit.domain} TXT \"v=STSv1; id=...\" and "
                f"serve a policy at "
                f"https://mta-sts.{audit.domain}/.well-known/mta-sts.txt "
                f"(start with mode: testing).",
            ))
        elif audit.mta_sts.policy_fetched and audit.mta_sts.mode != "enforce":
            findings.append(MailFinding(
                "MTA-STS", "LOW",
                f"MTA-STS is mode: {audit.mta_sts.mode or 'unknown'}",
                "Only 'enforce' causes senders to refuse a failed TLS "
                "connection.",
                "Move to mode: enforce once reports look clean.",
            ))
        elif (audit.mta_sts.dns_present and audit.mta_sts.fetch_attempted
                and not audit.mta_sts.policy_fetched):
            # Only a finding when we actually looked and it failed. With
            # --no-fetch we never looked, so claiming a problem would be a
            # false finding manufactured by our own flag.
            findings.append(MailFinding(
                "MTA-STS", "MEDIUM", "MTA-STS DNS record without a usable policy",
                f"The TXT record advertises a policy but it could not be "
                f"fetched ({audit.mta_sts.fetch_error or 'no response'}). "
                f"Senders that cannot fetch it fall back to no protection.",
                f"Make sure https://mta-sts.{audit.domain}"
                f"/.well-known/mta-sts.txt is served with a valid certificate.",
            ))

        if not audit.tls_rpt:
            findings.append(MailFinding(
                "TLS-RPT", "LOW", "No TLS reporting (TLS-RPT)",
                "You get no notification when inbound TLS fails or is "
                "downgraded.",
                f"Publish _smtp._tls.{audit.domain} TXT \"v=TLSRPTv1; "
                f"rua=mailto:tlsrpt@{audit.domain}\".",
            ))

    if not audit.dnssec:
        findings.append(MailFinding(
            "DNSSEC", "LOW", "Domain is not DNSSEC-signed",
            "Every mechanism here is published in DNS. Unsigned DNS can be "
            "spoofed, which undermines the records above.",
            "Enable DNSSEC with your registrar and DNS provider.",
        ))

    findings.sort(key=lambda f: -SEVERITY_ORDER.get(f.severity, 0))
    return findings


# ---------------------------------------------------------------------------
# Audit entry point
# ---------------------------------------------------------------------------

def audit_domain(domain: str, *, query=doh_query, fetch_policy: bool = True,
                 selectors=COMMON_SELECTORS, workers: int = 8) -> MailAudit:
    """Audit one domain's email authentication posture. Passive."""
    name = (domain or "").strip().rstrip(".").lower()
    name = re.sub(r"^https?://", "", name).split("/")[0]
    if "@" in name:
        name = name.split("@", 1)[1]
    if not name or "." not in name:
        raise MailAuditError(f"not a domain: {domain!r}")

    audit = MailAudit(domain=name)

    apex = query(name, "TXT")
    audit.dnssec = apex.authenticated

    mx_answer = query(name, "MX")
    audit.mx = sorted(mx_answer.records)

    audit.spf = check_spf(name, query)
    audit.dmarc = check_dmarc(name, query)
    audit.dkim = check_dkim(name, query, selectors=selectors, workers=workers)
    audit.mta_sts = check_mta_sts(name, query, fetch=fetch_policy)
    audit.tls_rpt = check_tls_rpt(name, query)

    audit.findings = _evaluate(audit)
    return audit


def meets_threshold(findings: list[MailFinding], threshold: str) -> bool:
    floor = SEVERITY_ORDER.get((threshold or "").upper())
    if floor is None:
        raise ValueError(f"unknown severity threshold: {threshold!r}")
    return any(SEVERITY_ORDER.get(f.severity, 0) >= floor for f in findings)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def recommended_records(audit: MailAudit) -> list[str]:
    """The DNS records to publish, as copy-pasteable lines."""
    domain = audit.domain
    lines: list[str] = []

    if not audit.spf.present:
        if audit.receives_mail:
            lines.append(f'{domain}.  IN TXT  "v=spf1 include:<provider> -all"')
        else:
            lines.append(f'{domain}.  IN TXT  "v=spf1 -all"'
                         "    ; domain sends no mail")
    elif audit.spf.all_qualifier in ("+", "?", ""):
        lines.append(f'{domain}.  IN TXT  "{audit.spf.raw} "'
                     "  ; change the all-qualifier to -all")

    if not audit.dmarc.present:
        lines.append(f'_dmarc.{domain}.  IN TXT  "v=DMARC1; p=none; '
                     f'rua=mailto:dmarc@{domain}; fo=1"'
                     "    ; start here, then raise to quarantine/reject")
    elif audit.spoofable or audit.subdomains_spoofable:
        lines.append(f'_dmarc.{domain}.  IN TXT  "v=DMARC1; p=reject; '
                     f'sp=reject; rua=mailto:dmarc@{domain}; fo=1"'
                     "    ; target state")
    elif not audit.dmarc.rua:
        # Enforcement is already in place but there is no reporting, so the
        # finding list has an item that the records list must not omit.
        existing = audit.dmarc.raw.rstrip().rstrip(";")
        lines.append(f'_dmarc.{domain}.  IN TXT  "{existing}; '
                     f'rua=mailto:dmarc@{domain}"'
                     "    ; add aggregate reporting")

    if audit.receives_mail and not audit.tls_rpt:
        lines.append(f'_smtp._tls.{domain}.  IN TXT  "v=TLSRPTv1; '
                     f'rua=mailto:tlsrpt@{domain}"')

    if audit.receives_mail and not audit.mta_sts.dns_present:
        lines.append(f'_mta-sts.{domain}.  IN TXT  "v=STSv1; id=<yyyymmddNN>"'
                     "    ; plus the policy file over HTTPS")

    return lines


def text_report(audit: MailAudit, *, verbose: bool = False) -> str:
    out: list[str] = []
    out.append("=" * 70)
    out.append(f"ColdLight email authentication posture: {audit.domain}")
    out.append("=" * 70)

    spf, dmarc = audit.spf, audit.dmarc

    if spf.present:
        note = f"  [{spf.all_meaning}]"
        out.append(f"SPF      : {spf.raw[:90]}")
        out.append(f"           all-qualifier: "
                   f"{spf.all_qualifier or '(none)'}{note}")
        limit_note = ""
        if spf.lookups > SPF_LOOKUP_LIMIT:
            limit_note = "  !! OVER THE LIMIT -- SPF may not evaluate at all"
        elif spf.lookup_truncated:
            limit_note = "  (expansion truncated; count is a lower bound)"
        out.append(f"           DNS lookups: {spf.lookups}/"
                   f"{SPF_LOOKUP_LIMIT}{limit_note}")
    else:
        out.append("SPF      : absent")

    if dmarc.present:
        out.append(f"DMARC    : p={dmarc.policy or '(missing)'}"
                   f"  sp={dmarc.subdomain_policy or '(inherits p)'}"
                   f"  pct={dmarc.percent}"
                   f"  aspf={dmarc.aspf} adkim={dmarc.adkim}")
        out.append(f"           reporting: "
                   f"{', '.join(dmarc.rua) if dmarc.rua else 'NONE (blind)'}")
    else:
        out.append("DMARC    : absent")

    if audit.dkim.wildcard:
        wildcard_key = audit.dkim.keys[0]
        state = "revoked (empty p=)" if wildcard_key.revoked else "live key"
        out.append(f"DKIM     : WILDCARD *._domainkey answers for any "
                   f"selector -- {state}")
        out.append("           per-selector probing is meaningless on this "
                   "domain")
    elif audit.dkim.found:
        for key in audit.dkim.keys:
            bits = f"{key.bits}-bit " if key.bits else ""
            flags = []
            if key.testing:
                flags.append("testing")
            if key.revoked:
                flags.append("REVOKED")
            suffix = f"  [{', '.join(flags)}]" if flags else ""
            out.append(f"DKIM     : selector '{key.selector}' "
                       f"{bits}{key.key_type}{suffix}")
    else:
        out.append(f"DKIM     : no key at {audit.dkim.selectors_probed} common "
                   f"selectors (inconclusive -- selectors are arbitrary)")

    if audit.mta_sts.dns_present:
        if audit.mta_sts.policy_fetched:
            out.append(f"MTA-STS  : present, mode={audit.mta_sts.mode or '?'}")
        elif audit.mta_sts.fetch_attempted:
            out.append(f"MTA-STS  : DNS record present, policy fetch FAILED "
                       f"({audit.mta_sts.fetch_error or 'no response'})")
        else:
            out.append("MTA-STS  : DNS record present (policy not fetched "
                       "-- re-run without --no-fetch to check its mode)")
    else:
        out.append("MTA-STS  : absent")

    out.append(f"TLS-RPT  : {'present' if audit.tls_rpt else 'absent'}")
    out.append(f"DNSSEC   : {'signed' if audit.dnssec else 'unsigned'}")
    if audit.null_mx:
        out.append("MX       : null MX ('0 .') -- domain accepts no mail "
                   "(RFC 7505)")
    else:
        out.append(f"MX       : {', '.join(audit.mx) if audit.mx else 'none'}")

    out.append("")
    out.append(audit.verdict)
    if audit.spoofable:
        if audit.protection_level == "none":
            out.append(f"  A forged `From: someone@{audit.domain}` would "
                       f"reach recipients' inboxes.")
        else:
            out.append(f"  A forged `From: someone@{audit.domain}` would "
                       f"still be ACCEPTED, not refused -- filed to spam or "
                       f"delivered,")
            out.append("  depending on the receiver. Recipients do read spam.")
        out.append("  Note: SPF cannot prevent this. SPF authenticates the "
                   "envelope sender,")
        out.append("  which users never see; only DMARC constrains the "
                   "visible From: header.")
    if audit.subdomains_spoofable and audit.dmarc.enforcing:
        out.append(f"  Subdomains of {audit.domain} remain spoofable "
                   f"(no sp= enforcement).")

    if audit.findings:
        out.append("")
        counts: dict[str, int] = {}
        for finding in audit.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        ordered = sorted(counts.items(),
                         key=lambda kv: -SEVERITY_ORDER.get(kv[0], 0))
        out.append(f"{len(audit.findings)} finding(s): "
                   + ", ".join(f"{k.lower()}={v}" for k, v in ordered))
        out.append("")
        for finding in audit.findings:
            out.append(f"{finding.severity:<9} [{finding.check}] {finding.title}")
            if verbose and finding.detail:
                out.append(f"          {finding.detail}")
            if finding.remediation:
                out.append(f"          fix: {finding.remediation}")
            out.append("")

    records = recommended_records(audit)
    if records:
        out.append("Recommended DNS records:")
        for line in records:
            out.append(f"  {line}")
        out.append("")

    return "\n".join(out)
