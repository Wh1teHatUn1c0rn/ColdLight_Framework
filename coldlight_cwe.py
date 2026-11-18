#!/usr/bin/env python3
"""
CWE enrichment: turn a bare "CWE-78" into something a developer can act on.

Printing `CWE-78` beside a finding tells a reader almost nothing. This maps
each weakness ColdLight emits to its MITRE name, a plain description of the flaw,
and concrete mitigations.

The catalogue is STATIC and bundled deliberately. cwe.mitre.org publishes the
corpus as a ~10 MB XML download; fetching and parsing that at scan time would
add a network dependency and a failure mode in order to produce text that
changes perhaps twice a year. These entries cover the weaknesses ColdLight
actually reports: every CWE in the code-scanner rule table, plus those NVD most
commonly assigns to dependency CVEs.

Names follow MITRE's catalogue. Descriptions and mitigations are written for a
developer reading a finding rather than copied verbatim, and a test asserts
every CWE our own rules emit has an entry here -- so the two cannot drift.

Stdlib only, no network.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Weakness:
    cwe: str
    name: str
    description: str
    mitigations: tuple[str, ...] = ()

    @property
    def url(self) -> str:
        return (f"https://cwe.mitre.org/data/definitions/"
                f"{self.cwe.split('-')[1]}.html")

    def to_dict(self) -> dict:
        data = asdict(self)
        data["mitigations"] = list(self.mitigations)
        data["url"] = self.url
        return data


def _w(cwe, name, description, *mitigations):
    return Weakness(cwe, name, description, tuple(mitigations))


CATALOG: dict[str, Weakness] = {w.cwe: w for w in (
    # ---- injection -------------------------------------------------------
    _w("CWE-20", "Improper Input Validation",
       "Input is used without checking that it is the expected type, length, "
       "format or range, so malformed or hostile values reach logic that "
       "assumes they are well formed.",
       "Validate against an allow-list of acceptable values, not a deny-list.",
       "Check type, length, format and range at the trust boundary.",
       "Reject invalid input outright rather than trying to sanitise it."),
    _w("CWE-74", "Improper Neutralization of Special Elements (Injection)",
       "Data is passed to a downstream interpreter -- a shell, SQL engine, "
       "template or parser -- without neutralising characters that interpreter "
       "treats as syntax, so data becomes instructions.",
       "Use the interpreter's parameterised interface instead of building "
       "strings.",
       "Encode for the specific downstream context, not generically."),
    _w("CWE-78", "Improper Neutralization of Special Elements used in an OS "
                 "Command (OS Command Injection)",
       "Attacker-influenced data reaches a shell, where metacharacters such as "
       "; | & and $( ) let an attacker append their own commands and run them "
       "with the process's privileges.",
       "Pass an argument list to exec/spawn so no shell parses the string "
       "(shell=False in Python, execFile rather than exec in Node).",
       "Where a shell is unavoidable, allow-list permitted values rather than "
       "escaping.",
       "Drop privileges so a successful injection gains as little as possible."),
    _w("CWE-79", "Improper Neutralization of Input During Web Page Generation "
                 "(Cross-site Scripting)",
       "Untrusted data is written into a page without context-correct "
       "encoding, so the browser executes attacker script with the victim's "
       "session.",
       "Render as text (textContent) rather than markup (innerHTML).",
       "Keep template auto-escaping on; mark only vetted values as safe.",
       "Add a Content-Security-Policy as defence in depth, not as the fix."),
    _w("CWE-89", "Improper Neutralization of Special Elements used in an SQL "
                 "Command (SQL Injection)",
       "Query text is assembled from untrusted input, letting an attacker "
       "alter the statement to read, change or destroy data outside their "
       "scope.",
       "Use parameterised queries or prepared statements for every value.",
       "Where an identifier must be dynamic, map it through a fixed "
       "allow-list.",
       "Grant the database account only the privileges the application needs."),
    _w("CWE-94", "Improper Control of Generation of Code (Code Injection)",
       "The application builds code from untrusted input and executes it, "
       "giving an attacker arbitrary execution in the process.",
       "Remove dynamic code construction; use data structures or a dispatch "
       "table.",
       "If dynamic behaviour is required, resolve names through an explicit "
       "allow-list of callables."),
    _w("CWE-95", "Improper Neutralization of Directives in Dynamically "
                 "Evaluated Code (Eval Injection)",
       "Input reaches eval/exec or new Function, so an attacker supplies code "
       "rather than data.",
       "Delete the eval. Parse structured data with a real parser such as "
       "json.loads.",
       "Replace dynamic dispatch with a mapping of permitted names to "
       "functions."),
    _w("CWE-917", "Expression Language Injection",
       "Untrusted input is evaluated as a template or expression-language "
       "expression, which commonly escalates to remote code execution.",
       "Never pass user input as a template; pass it as a bound variable.",
       "Use a sandboxed or logic-less template engine for untrusted content."),

    # ---- deserialisation and parsing -------------------------------------
    _w("CWE-502", "Deserialization of Untrusted Data",
       "Serialised data from an untrusted source is reconstituted into "
       "objects. Formats such as pickle, Java serialization and unsafe YAML "
       "can instantiate arbitrary types and invoke code while loading, so this "
       "is usually remote code execution rather than mere data tampering.",
       "Use a data-only format: JSON, or YAML via safe_load.",
       "If a rich format is unavoidable, sign the payload and verify the "
       "signature before deserialising.",
       "Restrict permitted classes with an allow-list where the runtime "
       "supports it."),
    _w("CWE-611", "Improper Restriction of XML External Entity Reference "
                  "(XXE)",
       "An XML parser resolves external entities, letting an attacker read "
       "local files or reach internal network services through the parser.",
       "Disable external entity and DTD processing in the parser.",
       "Prefer a parser hardened by default, such as defusedxml."),
    _w("CWE-1321", "Improperly Controlled Modification of Object Prototype "
                   "Attributes (Prototype Pollution)",
       "Merging untrusted keys into an object lets an attacker reach "
       "__proto__ or constructor and change behaviour for unrelated code "
       "paths.",
       "Reject __proto__, constructor and prototype keys when merging.",
       "Use Map, or Object.create(null), for untrusted key/value data."),

    # ---- paths and resources ---------------------------------------------
    _w("CWE-22", "Improper Limitation of a Pathname to a Restricted Directory "
                 "(Path Traversal)",
       "A filesystem path is built from untrusted input, so ../ sequences or "
       "absolute paths let an attacker read or write outside the intended "
       "directory.",
       "Resolve the path, then confirm it is still inside the intended root "
       "before opening it.",
       "Prefer an opaque identifier mapped server-side to a filename over "
       "accepting a path at all."),
    _w("CWE-434", "Unrestricted Upload of File with Dangerous Type",
       "Uploads are accepted without constraining type or location, so an "
       "attacker may store content the server will later execute.",
       "Allow-list extensions and verify content by inspection, not by the "
       "client's claim.",
       "Store uploads outside the web root and serve them through a handler.",
       "Rename to a generated name; never trust the supplied filename."),
    _w("CWE-668", "Exposure of Resource to Wrong Sphere",
       "A resource is reachable from a wider context than intended -- a "
       "service bound to every interface, or a file readable beyond its "
       "audience.",
       "Bind to the narrowest interface that works (127.0.0.1 where local).",
       "Put anything that must be reachable behind authentication and a "
       "firewall or reverse proxy."),
    _w("CWE-400", "Uncontrolled Resource Consumption",
       "Work is done in proportion to attacker-supplied input with no ceiling, "
       "so modest requests can exhaust CPU, memory or disk.",
       "Cap request and decompressed sizes, recursion depth and iteration "
       "counts.",
       "Apply rate limits and timeouts at the boundary."),
    _w("CWE-918", "Server-Side Request Forgery (SSRF)",
       "The server fetches a URL supplied by an attacker, which can reach "
       "internal services, cloud metadata endpoints or loopback addresses the "
       "attacker could not reach directly.",
       "Allow-list permitted hosts and schemes, and re-check after redirects.",
       "Block link-local and private ranges, including the cloud metadata "
       "address.",
       "Require IMDSv2 on AWS so metadata cannot be read with a bare GET."),

    # ---- secrets and cryptography ----------------------------------------
    _w("CWE-798", "Use of Hard-coded Credentials",
       "A credential is embedded in source or configuration. Anyone with read "
       "access to the repository -- including its history -- holds it, and "
       "rotation requires a code change.",
       "Load credentials from the environment, a secrets manager or an "
       "instance role.",
       "Treat any committed secret as compromised and rotate it, rather than "
       "only deleting the line.",
       "Scan history as well as the working tree: a deleted secret remains in "
       "past commits."),
    _w("CWE-312", "Cleartext Storage of Sensitive Information",
       "Sensitive data is written to disk, logs or a database without "
       "encryption, so anyone who can read the storage can read the data.",
       "Encrypt at rest and restrict filesystem permissions.",
       "Keep secrets and personal data out of logs entirely."),
    _w("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm",
       "An algorithm with known weaknesses is used -- MD5 or SHA-1 for "
       "integrity, DES, or a block cipher in ECB mode, which leaks structure "
       "because identical plaintext blocks encrypt identically.",
       "Use SHA-256 or better for integrity, and an authenticated mode such as "
       "AES-GCM for encryption.",
       "For passwords use a purpose-built KDF -- Argon2, scrypt or bcrypt -- "
       "never a plain hash."),
    _w("CWE-338", "Use of Cryptographically Weak Pseudo-Random Number "
                  "Generator",
       "A general-purpose RNG is used for a security value, so tokens, nonces "
       "or session identifiers can be predicted.",
       "Use the platform CSPRNG: secrets in Python, crypto.randomBytes in "
       "Node, crypto/rand in Go.",
       "Give tokens at least 128 bits of entropy."),
    _w("CWE-295", "Improper Certificate Validation",
       "TLS certificates are not validated, or validation is switched off, so "
       "an active network attacker can present their own certificate and read "
       "or alter the traffic. The connection still looks encrypted.",
       # nosec - this is the REMEDIATION TEXT for CWE-295, not a setting.
       # Naming the exact flags is what makes the advice actionable, so the
       # strings stay and the rule is suppressed with a reason instead.
       "Leave verification enabled; never set verify=False or "  # nosec
       "rejectUnauthorized: false.",  # nosec
       "For a private CA, trust its bundle explicitly rather than disabling "
       "the check.",
       "Pin or constrain the trust store where the peer set is known."),

    # ---- authentication and authorisation --------------------------------
    _w("CWE-287", "Improper Authentication",
       "The identity of a caller is not established correctly, so an attacker "
       "can act as another principal.",
       "Use a vetted authentication framework rather than bespoke logic.",
       "Enforce phishing-resistant multi-factor authentication where "
       "possible."),
    _w("CWE-862", "Missing Authorization",
       "An operation does not check whether the caller may perform it, so "
       "authenticated users reach data or actions outside their scope.",
       "Enforce authorisation server-side on every request, not in the UI.",
       "Default to deny and grant explicitly."),
    _w("CWE-863", "Incorrect Authorization",
       "An authorisation check exists but reaches the wrong conclusion: the "
       "wrong subject, object or role is compared.",
       "Centralise authorisation decisions in one tested component.",
       "Test negative cases -- each role attempting what it must not do."),
    _w("CWE-269", "Improper Privilege Management",
       "Privileges are granted or retained beyond what is required, widening "
       "the impact of any other flaw.",
       "Run with the least privilege that works, and drop privileges early.",
       "Separate duties so one compromised component cannot act alone."),
    _w("CWE-352", "Cross-Site Request Forgery (CSRF)",
       "A state-changing request is accepted on the strength of ambient "
       "credentials, so another site can cause it on the victim's behalf.",
       "Require an anti-CSRF token on every state-changing request.",
       "Set SameSite on session cookies."),

    # ---- memory safety (common in NVD dependency CVEs) -------------------
    _w("CWE-125", "Out-of-bounds Read",
       "A read occurs outside the bounds of a buffer, disclosing adjacent "
       "memory or crashing the process.",
       "Bounds-check every index and length before access.",
       "Prefer memory-safe constructs or languages for parsing untrusted "
       "input."),
    _w("CWE-787", "Out-of-bounds Write",
       "A write occurs outside the bounds of a buffer, corrupting memory and "
       "frequently enabling code execution.",
       "Validate lengths before copying, and use bounded APIs.",
       "Enable compiler and allocator hardening."),
    _w("CWE-416", "Use After Free",
       "Memory is used after release, giving unpredictable behaviour and often "
       "an exploitable primitive.",
       "Null pointers on free, and use ownership constructs that make reuse "
       "impossible.",
       "Run tests under a sanitiser such as ASan in CI."),
    _w("CWE-476", "NULL Pointer Dereference",
       "A null pointer is dereferenced, usually crashing the process and "
       "causing denial of service.",
       "Check allocations and lookups for null before use."),
    _w("CWE-190", "Integer Overflow or Wraparound",
       "Arithmetic exceeds the type's range and wraps, commonly producing an "
       "undersized allocation and a later overflow.",
       "Use checked arithmetic or a wider type for size calculations.",
       "Validate sizes against a maximum before allocating."),

    # ---- configuration and exposure --------------------------------------
    _w("CWE-16", "Configuration",
       "A security-relevant setting is wrong or left at an insecure default: a "
       "wildcard host or CORS origin, or an exposed administrative path.",
       "Pin allow-lists to the hosts and origins actually served.",
       "Review defaults per environment rather than inheriting development "
       "settings."),
    _w("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor",
       "Information that should be restricted is disclosed, through verbose "
       "errors, directory listings or debug output.",
       "Return generic errors to clients and keep detail in server-side logs.",
       "Remove debug endpoints and verbose headers from production builds."),
    _w("CWE-489", "Active Debug Code",
       "Debug functionality is enabled in a deployed build, typically leaking "
       "stack traces, configuration or an interactive console. Some debug "
       "consoles allow direct code execution.",
       "Drive debug mode from configuration that defaults to off.",
       "Fail the build or startup if debug is enabled with a production "
       "profile."),
    _w("CWE-617", "Reachable Assertion",
       "An assertion that attacker input can trigger aborts the process -- and "
       "assertions are often compiled out in release builds, so one used as a "
       "security check may simply vanish.",
       "Raise a real, handled error for input validation and security checks.",
       "Reserve assertions for invariants input cannot influence."),
    _w("CWE-749", "Exposed Dangerous Method or Function",
       "A powerful method is reachable by callers who should not have it, "
       "giving them capability the interface did not intend to offer.",
       "Restrict the method's visibility, or gate it behind an authorisation "
       "check."),
)}

# NVD uses these placeholders when no CWE was assigned. They are not
# weaknesses, so they resolve to nothing rather than to a bogus entry.
PLACEHOLDERS = {"NVD-CWE-NOINFO", "NVD-CWE-OTHER", "UNKNOWN", "NONE"}


def describe(cwe: str) -> Weakness | None:
    """Look up a weakness. Returns None for an unknown or placeholder id."""
    key = (cwe or "").strip().upper()
    if not key or key in PLACEHOLDERS:
        return None
    return CATALOG.get(key)


def summarise(cwe: str) -> str:
    """'CWE-78 — OS Command Injection', or the bare id when unknown."""
    weakness = describe(cwe)
    return f"{weakness.cwe} — {weakness.name}" if weakness else (cwe or "")


def known() -> set[str]:
    return set(CATALOG)
