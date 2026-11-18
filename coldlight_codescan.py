#!/usr/bin/env python3
"""
ColdLight static code analysis: flag insecure patterns and leaked secrets in a
codebase, each mapped to its CWE class.

This is a lightweight, dependency-free first pass -- it is NOT a replacement
for a full SAST engine (semgrep, CodeQL, bandit). It's tuned for the things a
red team actually finds and a blue team can actually fix: hardcoded
credentials, command injection sinks, unsafe deserialisation, disabled TLS
verification, weak hashing, and debug surfaces left enabled.

SCOPE BOUNDARY: read-only. It reports locations and CWE classes. It does not
exploit anything, and it redacts the secret values it discovers so the report
can be shared without leaking the credential.

Suppress a line with a trailing `# nosec` or `# coldlight:ignore` comment.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

SUPPRESS_RE = re.compile(r"#\s*(nosec|coldlight:ignore)\b|//\s*coldlight:ignore\b", re.I)

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "venv", ".venv", "env",
    "__pycache__", "dist", "build", ".tox", ".nox", ".mypy_cache",
    ".pytest_cache", "site-packages", ".idea", ".vscode", "vendor",
    "migrations", ".next", "coverage", "htmlcov",
}

# Extensions we bother reading at all.
TEXT_EXTENSIONS = {
    ".py", ".pyw", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".java",
    ".go", ".rb", ".php", ".cs", ".sh", ".bash", ".ps1", ".yml", ".yaml",
    ".json", ".ini", ".cfg", ".conf", ".toml", ".env", ".tf", ".tfvars",
    ".properties", ".xml", ".sql", ".c", ".cpp", ".h", ".swift", ".kt",
}

MAX_FILE_BYTES = 2_000_000  # skip anything bigger; it's data, not source
MAX_LINE_LEN = 4000         # minified bundles produce useless findings


@dataclass
class Rule:
    rule_id: str
    severity: str
    cwe: str
    title: str
    pattern: re.Pattern
    remediation: str
    extensions: frozenset[str] | None = None   # None == all
    redact: bool = False


def _rx(pattern: str, flags=0) -> re.Pattern:
    return re.compile(pattern, flags)


PY = frozenset({".py", ".pyw"})
JS = frozenset({".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"})
CONFIGISH = frozenset({".yml", ".yaml", ".json", ".ini", ".cfg", ".conf",
                       ".toml", ".env", ".properties", ".tf", ".tfvars", ".xml"})


RULES: list[Rule] = [
    # ---------------- secrets / credentials (CWE-798, CWE-312) -------------
    Rule(
        "SECRET-AWS-AKID", "CRITICAL", "CWE-798",
        "AWS access key id committed to source",
        _rx(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
        "Revoke the key immediately, then load credentials from the "
        "environment or an instance role.",
        redact=True,
    ),
    Rule(
        "SECRET-PRIVATE-KEY", "CRITICAL", "CWE-312",
        "Private key material in source",
        _rx(r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY(?: BLOCK)?-----"),
        "Rotate the key pair and move the private key to a secrets manager.",
        redact=True,
    ),
    Rule(
        "SECRET-GITHUB-PAT", "CRITICAL", "CWE-798",
        "GitHub token committed to source",
        _rx(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b"),
        "Revoke the token in GitHub settings and use a short-lived one.",
        redact=True,
    ),
    Rule(
        "SECRET-SLACK-TOKEN", "HIGH", "CWE-798",
        "Slack token committed to source",
        _rx(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
        "Revoke in the Slack app config; store in a secrets manager.",
        redact=True,
    ),
    Rule(
        "SECRET-PRIVATE-TOKEN", "HIGH", "CWE-798",
        "Hardcoded credential assignment",
        _rx(
            r"(?i)\b(?:api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?token|"
            r"auth[_-]?token|client[_-]?secret|password|passwd|pwd|private[_-]?key)\b"
            r"\s*[:=]\s*(['\"])(?![\s{<$])[^'\"\n]{8,}\1"
        ),
        "Read it from an environment variable or secrets manager. Rotate the "
        "value -- assume it is compromised once committed.",
        redact=True,
    ),
    Rule(
        "SECRET-CONN-STRING", "HIGH", "CWE-798",
        "Credentials embedded in a connection URI",
        _rx(
            r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|ftp|"
            r"https?)://[^\s:/@'\"]+:[^\s:/@'\"]+@"
        ),
        "Split the credential out of the URI and inject it at runtime.",
        redact=True,
    ),

    # ---------------- command injection (CWE-78) --------------------------
    Rule(
        "CMD-SHELL-TRUE", "HIGH", "CWE-78",
        "subprocess called with shell=True",
        _rx(r"\bshell\s*=\s*True\b"),
        "Pass a list of arguments and leave shell=False, so the shell never "
        "parses attacker-controlled text.",
        extensions=PY,
    ),
    Rule(
        "CMD-OS-SYSTEM", "HIGH", "CWE-78",
        "os.system / os.popen invokes a shell",
        _rx(r"\bos\.(?:system|popen)\s*\("),
        "Use subprocess.run([...]) with an argument list.",
        extensions=PY,
    ),
    Rule(
        "CMD-NODE-EXEC", "HIGH", "CWE-78",
        "child_process.exec invokes a shell",
        _rx(r"\bchild_process\s*\.\s*exec(?:Sync)?\s*\(|\bexec(?:Sync)?\s*\(\s*`"),
        "Use execFile/spawn with an argument array instead of exec.",
        extensions=JS,
    ),

    # ---------------- code injection (CWE-95) -----------------------------
    Rule(
        "CODE-EVAL", "HIGH", "CWE-95",
        "Dynamic code evaluation (eval/exec)",
        _rx(r"(?<![\w.])(?:eval|exec)\s*\("),
        "Remove it. If you need dynamic dispatch, use an explicit allow-list "
        "mapping of names to callables.",
        extensions=PY | JS,
    ),
    Rule(
        "CODE-NEW-FUNCTION", "MEDIUM", "CWE-95",
        "new Function() compiles a string as code",
        _rx(r"\bnew\s+Function\s*\("),
        "Replace with a static function or an allow-listed lookup table.",
        extensions=JS,
    ),

    # ---------------- unsafe deserialisation (CWE-502) --------------------
    Rule(
        "DESER-PICKLE", "HIGH", "CWE-502",
        "Unsafe deserialisation via pickle/marshal/shelve",
        _rx(r"\b(?:pickle|cPickle|_pickle|marshal)\s*\.\s*loads?\s*\("),
        "Never unpickle untrusted data -- it is arbitrary code execution. Use "
        "JSON, or sign the payload and verify before loading.",
        extensions=PY,
    ),
    Rule(
        "DESER-YAML-LOAD", "HIGH", "CWE-502",
        "yaml.load without a safe loader",
        _rx(r"\byaml\s*\.\s*load\s*\((?![^)]*Safe(?:Loader)?)"),
        "Use yaml.safe_load(), or pass Loader=yaml.SafeLoader.",
        extensions=PY,
    ),

    # ---------------- SQL injection (CWE-89) ------------------------------
    Rule(
        "SQLI-FSTRING", "HIGH", "CWE-89",
        "SQL query built by string interpolation",
        # Both branches require actual SQL in the string. Without that, any
        # f-string passed to a function called `query` matched -- a DNS lookup
        # like query(f"_dmarc.{domain}") is not SQL injection.
        _rx(
            r"(?i)\b(?:execute|executemany|executescript|raw|query)\s*\(\s*"
            r"(?:"
            r"f['\"][^'\"]*?\b(?:select|insert|update|delete|drop)\b"
            r"|"
            r"['\"][^'\"]*?\b(?:select|insert|update|delete|drop)\b"
            r"[^'\"]*?['\"]\s*(?:%|\+|\.format\b)"
            r")"
        ),
        "Use parameterised queries: cursor.execute(sql, params). Never "
        "concatenate user input into SQL.",
    ),

    # ---------------- transport security (CWE-295) ------------------------
    Rule(
        "TLS-VERIFY-OFF", "HIGH", "CWE-295",
        "TLS certificate verification disabled",
        _rx(r"\bverify\s*=\s*False\b|\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|"
            r"\brejectUnauthorized\s*:\s*false\b|_create_unverified_context\s*\("),
        "Leave verification on. For a private CA, pass its bundle via "
        "verify='/path/ca.pem' instead of disabling the check.",
    ),
    Rule(
        "TLS-INSECURE-CURL", "MEDIUM", "CWE-295",
        "curl/wget invoked with certificate checks disabled",
        _rx(r"\b(?:curl\b[^\n]*\s(?:-k|--insecure)\b|wget\b[^\n]*--no-check-certificate\b)"),
        "Remove -k/--insecure; trust the proper CA bundle instead.",
    ),

    # ---------------- weak crypto (CWE-327, CWE-338) ----------------------
    Rule(
        "CRYPTO-WEAK-HASH", "MEDIUM", "CWE-327",
        "Weak hash algorithm (MD5/SHA1)",
        _rx(r"\bhashlib\s*\.\s*(?:md5|sha1)\s*\(|\bcreateHash\s*\(\s*['\"](?:md5|sha1)['\"]"),
        "Use SHA-256+ for integrity. For passwords use bcrypt, scrypt or "
        "Argon2 -- never a bare hash.",
    ),
    Rule(
        "CRYPTO-WEAK-RANDOM", "MEDIUM", "CWE-338",
        "Non-cryptographic RNG used for a security value",
        # The security keyword may sit on either side of the call, so match
        # both orders: `token = random.randint(..)` and `random.choice(key_chars)`.
        _rx(
            r"(?i)(?:"
            r"\b(?:token|secret|password|passwd|nonce|salt|key|otp|session|csrf)\b"
            r"[^\n]{0,80}?"
            r"\b(?:random\s*\.\s*(?:random|randint|choice|randrange|sample|shuffle)"
            r"|Math\s*\.\s*random)\s*\("
            r"|"
            r"\b(?:random\s*\.\s*(?:random|randint|choice|randrange|sample|shuffle)"
            r"|Math\s*\.\s*random)\s*\("
            r"[^\n]{0,80}?"
            r"\b(?:token|secret|password|passwd|nonce|salt|key|otp|session|csrf)\b"
            r")"
        ),
        "Use the secrets module (Python) or crypto.randomBytes (Node).",
    ),
    Rule(
        "CRYPTO-ECB-MODE", "MEDIUM", "CWE-327",
        "Block cipher in ECB mode",
        _rx(r"\bMODE_ECB\b|['\"][a-z0-9-]+-ecb['\"]"),
        "Use an authenticated mode such as AES-GCM.",
    ),

    # ---------------- XSS / templating (CWE-79) ---------------------------
    Rule(
        "XSS-INNERHTML", "MEDIUM", "CWE-79",
        "Assignment to innerHTML / outerHTML",
        _rx(r"\.(?:inner|outer)HTML\s*="),
        "Use textContent, or sanitise with DOMPurify before injecting HTML.",
        extensions=JS,
    ),
    Rule(
        "XSS-DANGEROUS-HTML", "MEDIUM", "CWE-79",
        "React dangerouslySetInnerHTML",
        _rx(r"\bdangerouslySetInnerHTML\b"),
        "Sanitise the value first, or render it as text.",
        extensions=JS,
    ),
    Rule(
        "XSS-AUTOESCAPE-OFF", "HIGH", "CWE-79",
        "Template auto-escaping disabled",
        _rx(r"\bautoescape\s*=\s*False\b"),
        "Leave autoescape on and mark only vetted values as safe.",
        extensions=PY,
    ),

    # ---------------- path traversal (CWE-22) -----------------------------
    Rule(
        "PATH-TRAVERSAL", "MEDIUM", "CWE-22",
        "Filesystem path built from request data",
        _rx(
            r"(?i)\b(?:open|send_file|sendFile|readFile(?:Sync)?|createReadStream)\s*\("
            r"[^)\n]*\b(?:request|req)\b[^)\n]*\)"
        ),
        "Resolve the path and confirm it stays inside the intended directory "
        "(os.path.realpath + prefix check) before opening it.",
    ),

    # ---------------- debug / exposure surfaces (CWE-489, CWE-16) ---------
    Rule(
        "CONF-DEBUG-ON", "MEDIUM", "CWE-489",
        "Debug mode enabled",
        # The key may be quoted (JSON/YAML/dict): "debug": true
        _rx(r"(?i)\bdebug['\"]?\s*[:=]\s*(?:True|['\"]?true['\"]?)\b"),
        "Debug mode leaks stack traces and can expose an interactive console. "
        "Drive it from an environment variable, defaulting to off.",
    ),
    Rule(
        "CONF-WILDCARD-HOSTS", "MEDIUM", "CWE-16",
        "Wildcard host / CORS origin allow-list",
        _rx(r"ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*['\"]|"
            r"Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*['\"]|"
            r"\borigin\s*:\s*['\"]\*['\"]", re.I),
        "Pin the allow-list to the hostnames you actually serve.",
    ),
    Rule(
        "CONF-BIND-ALL", "LOW", "CWE-668",
        "Service bound to all interfaces",
        _rx(r"['\"]0\.0\.0\.0['\"]|\bhost\s*=\s*['\"]0\.0\.0\.0['\"]"),
        "Bind to 127.0.0.1 unless the service is meant to be reachable, and "
        "put it behind a firewall or reverse proxy if it is.",
    ),
    Rule(
        "CONF-ASSERT-AUTH", "LOW", "CWE-617",
        "assert used for a security check",
        _rx(r"\bassert\b[^\n]*\b(?:auth|admin|permission|is_staff|role|token)\b"),
        "asserts are stripped under python -O. Raise a real exception.",
        extensions=PY,
    ),
]


# Every severity in this module comes from the rule table below -- our
# judgement, not a published rating. Declared so a report can distinguish it
# from an NVD CVSS score. The literal is checked against
# coldlight_vulnintel.SEVERITY_SOURCES by a test, so the two cannot drift.
SEVERITY_SOURCE = "coldlight-rule"


@dataclass
class CodeFinding:
    rule_id: str
    severity: str
    cwe: str
    title: str
    file: str
    line: int
    snippet: str
    remediation: str = ""
    severity_source: str = SEVERITY_SOURCE

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def rank(self) -> tuple:
        return (-SEVERITY_ORDER.get(self.severity.upper(), 0), self.file, self.line)


@dataclass
class CodeScanResult:
    findings: list[CodeFinding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    errors: list[str] = field(default_factory=list)


_QUOTED = re.compile(r"""(['"])([^'"\n]{4,})\1""")


def redact(line: str) -> str:
    """Mask quoted values and long opaque tokens so a report can be shared."""
    out = _QUOTED.sub(lambda m: f"{m.group(1)}***REDACTED***{m.group(1)}", line)
    # Catch unquoted high-entropy-looking tokens too (env files, YAML).
    out = re.sub(
        r"(?<=[:=]\s)([A-Za-z0-9/+_\-]{16,})(?=\s*$)", "***REDACTED***", out
    )
    out = re.sub(
        r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b", "***REDACTED***", out
    )
    out = re.sub(
        r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b",
        "***REDACTED***", out,
    )
    out = re.sub(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b", "***REDACTED***", out)
    out = re.sub(r"(://[^\s:/@'\"]+):([^\s:/@'\"]+)(?=@)", r"\1:***REDACTED***", out)
    return out


def is_excluded(path: Path, root: Path, patterns: list[str] | None) -> bool:
    """True if `path` matches any caller-supplied exclude glob.

    Patterns match the path relative to the scan root (posix separators), so
    `--exclude "tests/*"` works the same on Windows. A bare directory name is
    treated as that whole subtree.
    """
    if not patterns:
        return False
    try:
        rel = path.resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        rel = path.as_posix()
    full = path.as_posix()

    for raw in patterns:
        pattern = raw.replace("\\", "/").rstrip("/")
        if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(full, pattern):
            return True
        # "tests" should also mean everything under tests/
        if rel == pattern or rel.startswith(pattern + "/"):
            return True
        if fnmatch.fnmatch(rel, pattern + "/*"):
            return True
    return False


def iter_source_files(root: str | Path, exclude: list[str] | None = None):
    """Yield candidate source files under `root`, skipping vendored trees."""
    root = Path(root)
    if root.is_file():
        if not is_excluded(root, root.parent, exclude):
            yield root
        return

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in SKIP_DIRS and not (d.startswith(".") and d != ".")
            and not is_excluded(Path(dirpath) / d, root, exclude)
        ]
        for name in filenames:
            path = Path(dirpath) / name
            if path.suffix.lower() not in TEXT_EXTENSIONS and name not in (
                ".env", "Dockerfile"
            ):
                continue
            if is_excluded(path, root, exclude):
                continue
            yield path


def scan_file(path: Path, rules: list[Rule] | None = None) -> list[CodeFinding]:
    """Apply every applicable rule to one file."""
    rules = rules if rules is not None else RULES
    ext = path.suffix.lower()
    applicable = [
        r for r in rules if r.extensions is None or ext in r.extensions
    ]
    if not applicable:
        return []

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    findings: list[CodeFinding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > MAX_LINE_LEN or SUPPRESS_RE.search(line):
            continue
        stripped = line.strip()
        # Skip obvious comment-only lines for code rules to cut false positives.
        if stripped.startswith(("#", "//", "*")) and "BEGIN" not in stripped:
            continue

        for rule in applicable:
            if not rule.pattern.search(line):
                continue
            snippet = redact(line) if rule.redact else line
            snippet = snippet.strip()[:200]
            findings.append(CodeFinding(
                rule_id=rule.rule_id,
                severity=rule.severity,
                cwe=rule.cwe,
                title=rule.title,
                file=str(path),
                line=lineno,
                snippet=snippet,
                remediation=rule.remediation,
            ))
    return findings


def scan_code(root: str | Path, rules: list[Rule] | None = None,
              exclude: list[str] | None = None) -> CodeScanResult:
    """Walk a tree and report insecure patterns. Read-only."""
    result = CodeScanResult()
    for path in iter_source_files(root, exclude):
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                result.files_skipped += 1
                continue
        except OSError:
            result.files_skipped += 1
            continue

        result.files_scanned += 1
        try:
            result.findings.extend(scan_file(path, rules))
        except Exception as exc:  # noqa: BLE001 - never let one file kill the scan
            result.errors.append(f"{path}: {exc}")

    result.findings.sort(key=lambda f: f.rank)
    return result


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def severity_counts(findings: list[CodeFinding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.upper()] = counts.get(f.severity.upper(), 0) + 1
    return counts


def cwe_counts(findings: list[CodeFinding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.cwe] = counts.get(f.cwe, 0) + 1
    return counts


def meets_threshold(findings: list[CodeFinding], threshold: str) -> bool:
    floor = SEVERITY_ORDER.get((threshold or "").upper())
    if floor is None:
        raise ValueError(f"unknown severity threshold: {threshold!r}")
    return any(
        SEVERITY_ORDER.get(f.severity.upper(), 0) >= floor for f in findings
    )


def text_report(result: CodeScanResult, *, show_remediation: bool = True) -> str:
    out: list[str] = []
    counts = severity_counts(result.findings)

    out.append("=" * 68)
    out.append("ColdLight static code analysis")
    out.append("=" * 68)
    out.append(f"files scanned : {result.files_scanned}")
    out.append(f"findings      : {len(result.findings)}")
    if counts:
        ordered = sorted(counts.items(), key=lambda kv: -SEVERITY_ORDER.get(kv[0], 0))
        out.append("  by severity : " +
                   ", ".join(f"{k.lower()}={v}" for k, v in ordered))
    cwes = cwe_counts(result.findings)
    if cwes:
        top = sorted(cwes.items(), key=lambda kv: -kv[1])[:6]
        out.append("  top CWEs    : " + ", ".join(f"{k}({v})" for k, v in top))

    if result.findings:
        out.append("")
        current_rule = None
        for f in result.findings:
            if f.rule_id != current_rule:
                current_rule = f.rule_id
                out.append(f"{f.severity.upper():<8} {f.cwe:<9} {f.title}  [{f.rule_id}]")
                if show_remediation and f.remediation:
                    out.append(f"         fix: {f.remediation}")
            out.append(f"         {f.file}:{f.line}")
            out.append(f"             | {f.snippet}")
        out.append("")

    if result.errors:
        out.append(f"{len(result.errors)} error(s):")
        for err in result.errors[:10]:
            out.append(f"  - {err}")

    out.append("Note: pattern-based first pass. Confirm each finding in context; "
               "pair with semgrep/CodeQL for depth.")
    return "\n".join(out)


def json_report(result: CodeScanResult) -> dict:
    return {
        "tool": "coldlight codescan",
        "files_scanned": result.files_scanned,
        "severity_counts": severity_counts(result.findings),
        "cwe_counts": cwe_counts(result.findings),
        "findings": [f.to_dict() for f in result.findings],
        "errors": result.errors,
    }
