# ColdLight — Security Assessment Framework

[![CI](https://github.com/Wh1teHatUn1c0rn/ColdLight_Framework/actions/workflows/ci.yml/badge.svg)](https://github.com/Wh1teHatUn1c0rn/ColdLight_Framework/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)
[![Dependencies](https://img.shields.io/badge/runtime%20deps-none-brightgreen)](pyproject.toml)

A **benign** red-team assessment toolkit. Seven parts, one idea: find the
problem, prove you looked, and say plainly what you did not check.

1. **Awareness testing** — a USB-drop / QR / link campaign that measures how many
   people run a file from an unknown USB stick (or click an unknown link), and
   teaches them in the moment — plus an **email authentication audit** that
   shows whether an attacker could spoof your own domain in the first place.
2. **Vulnerability assessment** — dependency, SBOM and source-code scanning that
   pulls known-vulnerability data from the official feeds (NVD/MITRE, OSV.dev,
   CISA KEV) and reports what's exposed, how bad it is, and how to fix it —
   then emits **VEX** (OpenVEX / CycloneDX / CSAF) to state which findings
   actually apply.
3. **Verifiable results** — an in-toto attestation binding the report to its
   inputs *and its scope*, signed via GnuPG/OpenSSL.
4. **An assurance ledger** — the differentiator: a per-class record of what
   was assessed, what was partial, and what nobody looked at, including
   classes this tool cannot cover at all.
5. **One-command assessment** — `coldlight assess` runs every stage from a
   profile and produces the report, reporting any stage that failed as NOT
   ASSESSED rather than as clean.
6. **Purple-team validation** — maps what the test exercises to MITRE ATT&CK,
   ships Sigma rules, and turns each recorded hit into a worksheet telling the
   blue team exactly where to look to see whether they'd have caught it.
7. **The deliverable** — aggregates all of the above into one report (HTML,
   Markdown or JSON), with findings triaged rather than dumped.

Every part **finds and reports** problems. None of them exploits anything: no
persistence, no shellcode, no credential access, no evasion, no exploit
execution. That restraint is intentional — the deliverable of an assessment is a
prioritised finding and a teachable moment, not a foothold.

## Try it in thirty seconds

No dependencies, no API key, no account. The runtime is stdlib-only.

```bash
git clone https://github.com/Wh1teHatUn1c0rn/ColdLight_Framework
cd ColdLight_Framework

python coldlight.py doctor              # will any of this work on this box?
python coldlight.py scan code .         # insecure patterns + leaked secrets
python coldlight.py scan deps .         # dependencies vs OSV.dev + CISA KEV
python coldlight.py mail audit example.com   # can someone spoof this domain?
```

`coldlight doctor` is the one to run first: it reports which commands will
work here and which will not, rather than letting you find out halfway
through an engagement.

Security policy, and the list of things this tool will never do, are in
[SECURITY.md](SECURITY.md).

## Files

| File | Purpose |
|------|---------|
| `coldlight.py` | **The CLI.** `new` / `validate` / `build` — drives everything. |
| `coldlight_config.py` | Campaign config schema, loading, and validation (shared by CLI + payload). |
| `coldlight_awareness.py` | The payload. Config-driven; logs the run, shows an awareness message, optional beacon. |
| `campaign.toml` | Campaign config you edit (engagement id, auth ref, sponsor, lure, collector…). |
| `awareness_message.html` | Training page template; the CLI fills in the real values. |
| `coldlight_report.py` | SQLite storage, de-dup, metrics, CSV export (powers `coldlight report`). |
| `coldlight_collector.py` | Token-authed collection server + dashboard (powers `coldlight serve`). |
| `coldlight_sign.py` | Authenticode signing helper (powers `coldlight sign`). |
| `coldlight_qr.py` | QR-code poster generator (powers `coldlight qr`). |
| `coldlight_vulnintel.py` | Known-vulnerability intelligence: NVD/MITRE, OSV.dev, CISA KEV (powers `scan deps`, `cve`, `vulns`, `kev`). |
| `coldlight_codescan.py` | Static analysis: insecure patterns + leaked secrets, CWE-mapped (powers `scan code`). |
| `coldlight_aisec.py` | AI/ML security: unsafe model deserialisation, prompt-injection sinks, agent permissions — OWASP LLM / ATLAS mapped (powers `scan ai`). |
| `coldlight_history.py` | Secrets committed to git history, including ones later deleted from the working tree; shallow clones are refused rather than reported clean (powers `scan history`). |
| `coldlight_trust.py` | The one TLS trust store every network call shares: CA-bundle precedence, a verifying context, and no way to weaken it. |
| `coldlight_doctor.py` | Preflight: which external dependencies work on this machine, and which commands stop working without them (powers `doctor`, and the check `assess` opens with). |
| `coldlight_scope.py` | The authorization gate: declared targets, bounded wildcards, expiry, recorded decisions (powers `scope`). Deny by default. |
| `coldlight_canary.py` | Benign injection susceptibility probing of a live endpoint — canary tokens only, no jailbreak corpus (powers `probe`). |
| `coldlight_sbom.py` | CycloneDX / SPDX ingest and purl→ecosystem mapping (powers `scan sbom`). |
| `coldlight_mail.py` | Email authentication posture: SPF/DKIM/DMARC/MTA-STS/TLS-RPT/DNSSEC over DNS-over-HTTPS (powers `mail`). |
| `coldlight_cwe.py` | Bundled CWE catalogue: MITRE name, description and mitigations per weakness. No network. |
| `coldlight_exploitintel.py` | EPSS scores (FIRST.org) and Exploit-DB index metadata. |
| `coldlight_attest.py` | Verifiable results: in-toto attestation, delegated signing, tamper detection (powers `attest`). |
| `coldlight_assurance.py` | The coverage ledger: what was assessed, what was partial, and what nobody looked at (powers `assurance`). |
| `coldlight_assess.py` | The one-command orchestrator: runs every stage, records failures honestly, builds the report (powers `assess`). |
| `coldlight_baseline.py` | Baseline/diff: stable fingerprints so scans report only what's new (`--baseline`). |
| `coldlight_engagement.py` | The deliverable: aggregates every module's findings into one HTML/Markdown/JSON report (powers `engagement`). |
| `coldlight_vex.py` | VEX: triage model, conformance validation, OpenVEX / CycloneDX / CSAF emitters (powers `vex`). |
| `coldlight_detect.py` | Purple-team layer: ATT&CK mapping, Sigma rules, Navigator layer, validation worksheet (powers `detect`). |
| `tests/` | pytest suite — 1172 tests, no network required. |
| `build_bundle.py` | Dev tool: builds the single-file `dist/coldlight-standalone.py` and verifies it round-trips. |
| `pyproject.toml` | Packaging and metadata; installs the `coldlight` console script. Also holds the pytest config. |
| `.github/workflows/ci.yml` | Tests on Windows + Linux × Python 3.11–3.13, a self-scan, and a wheel-install check. |
| `CHANGELOG.md` | Release notes, including the bugs found and fixed along the way. |
| `.gitignore` | Excludes campaign results (they contain PII) and signing material; **keeps** `.coldlight/baseline.json`, which is meant to be reviewed. |

## Installing

```bash
pip install .                 # the assessment commands; no dependencies at all
pip install ".[dev]"          # + pytest, pyyaml (to run the test suite)
pip install ".[build,qr]"     # + PyInstaller and qrcode, for campaign building
coldlight --version
```

**The runtime is stdlib-only.** `scan`, `mail`, `detect`, `vex`, `engagement`,
`cve`, `vulns`, `kev`, `report` and `purge` all run on a bare Python 3.11+
(3.11 is the floor because of `tomllib`). Verified by installing the wheel into
an empty virtualenv — `pip list` shows only `pip` and `coldlight` — and running
those commands from it. Extras are needed for exactly two commands: `build`
(PyInstaller) and `qr` (qrcode); both say so clearly rather than failing with a
traceback.

### One caveat: run `new` and `build` from a checkout

ColdLight ships as flat modules rather than a package, so an installed wheel does
not carry `campaign.toml` or `awareness_message.html` beside them. Those two
commands need the templates, so run them from a clone:

```bash
git clone <repo> && cd coldlight
python coldlight.py new october-drop
python coldlight.py build campaigns/october-drop/campaign.toml
```

Rather than silently writing an empty config, `new` refuses and explains, and
`build` warns if the training page template is missing. Everything else works
identically installed or from a checkout.

*(The tidier fix is restructuring into a `coldlight/` package with the templates
as package data. It is deliberately not done yet: it would rewrite every import
**and** the PyInstaller `--paths` plumbing that lets the frozen payload import
`coldlight_config`, and a frozen exe cannot be covered by the test suite — so the
failure mode is a silent runtime break in the built payload. Not worth it for
tidiness.)*

## Single-file build (drop it on any box)

Sometimes you are handed a jump box and told "assess this". No pip, no venv, no
network to PyPI.

```bash
python build_bundle.py --verify        # -> dist/coldlight-standalone.py  (~301 KiB)

# then just copy that one file and run it
scp dist/coldlight-standalone.py host:/tmp/coldlight.py
python /tmp/coldlight.py scan code /srv/app
python /tmp/coldlight.py mail audit corp.example.com
python /tmp/coldlight.py engagement --vuln v.json --code c.json --out report.html
```

One file, Python 3.11+, **nothing else**. Verified by running it on an
interpreter created with `venv --without-pip`, where no third-party module is
importable at all.

### How it works, and why it can't corrupt the code

Each module is zlib-compressed and base64-encoded into a table, and a
meta-path finder serves those sources to the import system on demand — so
`import coldlight_config` inside the bundled code resolves exactly as it does
from real files, with **no rewriting of the sources** and no dependence on
load order.

The encoding is base64 rather than inlined text on purpose. These modules are
full of regexes and Windows paths; any text-embedding scheme has to escape
them, and a bundler that silently mangles one backslash yields a scanner whose
rules quietly match nothing — a corrupted security tool that still reports
"clean". That failure would be invisible. Compressed base64 cannot corrupt the
payload, and the build proves it:

```
[1/3] round-trip: 27 module(s) + 2 asset(s) OK -- byte-identical
[2/3] test suite against extracted sources: 1140 passed, 32 skipped
[3/3] CLI smoke tests: 3 passed
```

Step 2 is the one that matters: the suite runs against the code *extracted
back out of the bundle*, so the file you ship is provably the code the tests
passed on. The 32 skips are accounted for and expected — the 28 bundler
tests plus 3 repo-metadata tests, none of which can run outside a checkout
(`build_bundle.py` is a dev tool and is deliberately not embedded in its own
output), and one signing test that needs GnuPG on the box. 1140 + 32 = the
full 1172.

### Auditable, and more capable than the wheel

```bash
python coldlight-standalone.py --extract ./coldlight-src   # verbatim sources back out
```

Every embedded module and template is written out byte-for-byte, so anyone
asked to run this on their estate can read exactly what it does. The header
also carries a SHA-256 of the sources it was built from.

Because the campaign templates are embedded too, **`new` and `build` work from
the standalone file** — which the installed wheel cannot do. Templates come
from the bundle; output still goes to your working directory.

One honest note: scanning a directory containing this file will flag an
`exec()` at CWE-95. That is a **true positive** — the loader genuinely does
dynamic execution, as every bundler must. It carries a `# nosec` with the
reasoning inline, so it reads as a documented decision rather than a mystery
hit.

## Continuous integration

`.github/workflows/ci.yml` has three jobs:

| Job | What it does |
|-----|--------------|
| **tests** | The suite on Windows **and** Linux × Python 3.11/3.12/3.13. It must pass with **no network access** — every upstream HTTP call is stubbed. Also asserts the `coldlight` console script installed. |
| **dogfood** | Runs `scan code` against ColdLight' own source with `--baseline`, so it fails only on *new* findings. |
| **single-file** | Builds `coldlight-standalone.py`, verifies byte-identical extraction and runs the suite against the extracted sources, then runs it on an interpreter with nothing installed. |
| **build** | Builds the sdist and wheel, installs the wheel into a clean venv, and runs the CLI there — catching anything that only breaks once packaged. |

Honest caveat: the suite is verified locally on **Windows only**. The Linux leg
is included because nothing in it looks platform-specific — the only `C:\`
strings in the tests are Sigma-rule literals, not filesystem access, and
`tkinter` is imported lazily inside `show_message` so a headless runner can
still import the payload — but the first CI run is what proves it.

## Preflight: `coldlight doctor`

ColdLight is stdlib-only at runtime, but it is not self-contained. It leans on a
`git` binary, a current CA bundle, two public DNS-over-HTTPS resolvers, four
vulnerability and exploit feeds, and optionally GnuPG or OpenSSL. On a jump
box that was
handed to you an hour ago, some of that will be missing or firewalled — and
without a preflight you learn which one halfway through an engagement, from
whichever stage happened to need it first.

```bash
coldlight doctor                            # check everything
coldlight doctor --offline                  # local dependencies only
coldlight doctor --profile assessment.toml  # only what this engagement needs
```

The report is organised around **commands, not binaries**, because that is the
question you actually have:

```
External tools
----------------------------------------------------------------------
  git                      ok           git version 2.43.0
  GnuPG                    ok           gpg (GnuPG) 2.4.4
  signtool (Authenticode)  UNAVAILABLE  signtool is not installed or not on PATH
                                        -> install the Windows SDK, or skip Authenticode signing

External services
----------------------------------------------------------------------
  NVD (CVE records)        ok           services.nvd.nist.gov answered HTTP 200
  OSV.dev (advisories)     ok           api.osv.dev answered HTTP 200
  Exploit-DB index         DEGRADED     raw.githubusercontent.com answered HTTP 200
                                        (primary unreachable: gitlab.com: timed out)
                                        -> the primary source is blocked here; the mirror is in use
  DNS-over-HTTPS           DEGRADED     dns.google answered; cloudflare-dns.com: connection refused
                                        -> one resolver is enough, so `mail audit` works

Commands that will not work on this machine
----------------------------------------------------------------------
  sign   signtool is not installed or not on PATH
```

Exit codes: **0** everything checked is healthy, **1** some commands will not
work, **2** ColdLight cannot run here at all (only a Python below 3.11 or a
missing `tomllib` gets you a 2).

### It checks the same code path the real command uses

The TLS probes go through `coldlight_trust.ssl_context()` and the DNS probes
through `coldlight_mail.doh_query()` — the actual functions, not re-implementations.
A doctor that opened its own socket with its own trust store could report a
healthy machine while every scan fails, which is worse than having no check.

This is also how the preflight found a real bug in ColdLight itself. Under a
deliberately broken `COLDLIGHT_CA_BUNDLE` every feed probe failed and DNS kept
answering — because `coldlight_mail` never imported the trust store and so used
the system one. The variable applied to *some* of the tool's connections and
silently not the rest. See **One trust store** below.

That is also why `DEGRADED` exists as a distinct state. A host that answers
`HTTP 403` proved DNS, TCP and TLS all work and is merely rate-limiting you;
calling that a connectivity failure sends you to debug the wrong layer.

### One resolver is enough, so one blocked resolver is not a failure

`mail audit` tries the DoH resolvers in order and needs exactly one to answer.
So DNS is a **single** check covering both, not one per resolver — otherwise a
blocked Cloudflare would report `mail audit` as broken while it works fine.
The per-resolver outcome still appears in the detail, because *which* one is
blocked is the part you act on.

### Skipped is never reported as healthy

`--offline` does not quietly produce a clean bill of health:

```
NOT CHECKED (6): NVD (CVE records), OSV.dev (advisories), CISA KEV catalog, ...
  Nothing was learned about these. A clean report above does not cover them.
```

Same rule as the assurance ledger and the shallow-clone refusal: *checked and
clean* and *nobody looked* are different findings. CI enforces it — an offline
run that reported any external service as `ok` fails the build.

### The probes carry nothing about the engagement

The preflight runs *before* an assessment and talks to five external services.
Every probe sends a fixed payload: a constant public package name for OSV, a
well-known CVE id for EPSS, `example.com` for DNS. No target, no domain under
test, no package or path from the project. A preflight that leaked the scope
to five third parties before the engagement started would be a defect, and
there is a test that fails if a future change makes one of these probes read
from its input.

The two multi-megabyte feeds (CISA KEV, the Exploit-DB index) are probed with
`HEAD`. A preflight that downloaded 20 MB would cost more than the command it
precedes.

### `--profile` checks only what the engagement needs

```
stages          : source code, git history, email posture

Checking only what this profile needs.

5 ok, 1 not checked  (0.2s)
...
Stages with no external dependency: source code
```

Nineteen checks narrow to six: no `PyInstaller`, no `GnuPG`, no `signtool`,
because nothing in this profile builds or signs anything. Stages that need
nothing external are *named* rather than omitted — "source code has no
external dependency" is information, not an empty row.

`assess` opens with this same check automatically, scoped to the stages the
profile configures:

```
Assessment: dependencies, source code, git history
Output    : out

preflight: git UNAVAILABLE -- git is not installed or not on PATH
preflight: these stages will fail: git history
preflight: running anyway -- a failed stage is reported as FAILED, never as clean
```

It reports; it does not gate. Aborting would throw away the stages that would
have worked, and the stage machinery already records a failure as `FAILED`.
Pass `--no-preflight` to skip it.

One honest limit: this checks **dependencies, not targets**. `git` being
installed does not mean your path is a repository, and a reachable NVD does not
mean your manifest parses. Those are the stages' job, and they still report
`FAILED` when they fail.

## One command: `coldlight assess`

A full engagement is otherwise five commands plus `engagement`, with wiring to
remember. This runs the lot:

```bash
coldlight assess --init assessment.toml     # scaffold a commented profile
coldlight assess --profile assessment.toml
```

```
Assessment: dependencies, source code, AI/ML systems, email posture, detection artifacts
Output    : out

[1/6] dependencies: 12 findings
[2/6] source code: 7 findings
[3/6] AI/ML systems: 5 findings, 1 code-executing model artifact(s)
[4/6] email posture: protected (full) — 3 findings
[5/6] detection artifacts: 4 Sigma rules, ATT&CK layer, checklist
[6/6] report: report.html, report.md

Stages: 6 ok, 0 failed
19 finding(s) covering 27 item(s)
  critical=5, high=8, medium=4, info=2

FAIL: findings at or above HIGH
```

Flags override the profile, so you can skip the file entirely:

```bash
coldlight assess --code . --deps . --ai . --domain corp.example.com \
    --baseline .coldlight/baseline.json --fail-on high --out-dir out
```

### A failed stage is never a clean stage

This is the rule the module exists to enforce. Break the email stage and
compare — the finding count drops from 14 to 11, which is exactly where a
reader could be misled:

```
Stages: 4 ok, 1 failed
  ok       dependencies          12 findings
  ok       source code           7 findings
  FAILED   email posture         MailAuditError: not a domain: 'localhost'
  ok       detection artifacts   4 Sigma rules, ATT&CK layer, checklist
  ok       report                report.html, report.md

11 finding(s) covering 19 item(s)

!! 1 stage(s) failed. The report marks those areas NOT ASSESSED.
   The findings above are therefore incomplete -- do not read them as a clean result.
```

…and the report itself says so, in Appendix B:

> The email posture stage FAILED and was not assessed (MailAuditError: not a
> domain: 'localhost'). Treat that area as UNKNOWN, not as clean — no finding
> from it appears in this report.

No stage can abort the run: one failure never costs you the other four.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | every stage ran, no gate tripped |
| `1` | a gate tripped — findings at or above `fail_on` (new-since-baseline if one is configured) |
| `2` | config error, **or a stage failed** — the assessment is incomplete, which outranks the findings gate |

`2` beating `1` is deliberate: a reader cannot trust totals from a run that
did not finish, so incompleteness is the more urgent signal.

### The output directory describes itself

```
out/
  deps.json  code.json  mail.json      # one artifact per stage, per target
  sigma/  attack_layer.json  blue_team_checklist.md
  report.html  report.md
  run.json                             # what this run did
```

Every number in the report traces back to the scan JSON that produced it.
`run.json` records stage statuses, errors, artifact paths, the gate result and
`"incomplete": true/false`, so the directory is machine-readable rather than a
pile of JSON to interpret.

A stage also **clears its own stale output before running**. Without that, a
failed stage would leave yesterday's `mail.json` in place: this run's report
would correctly ignore it, but anyone globbing `out/*.json` afterwards — or
re-running `engagement --mail out/mail.json` — would quietly mix in data from
a different assessment.

## The assurance ledger

Every scanner tells you what it found. Almost none tell you **what it never
looked at** — so a report with few findings reads as reassurance when it may
simply be narrow. This makes that the headline artifact.

```bash
coldlight assurance assessment/              # or it prints automatically after `assess`
coldlight assurance assessment/ --require-complete   # exit 1 if a class went unexamined
```

```
ASSURANCE LEDGER — what was assessed, and what nobody looked at
========================================================================

  class                                status        findings  checked
  ------------------------------------ ------------- --------  ------------
  Language dependencies                ASSESSED            12  2/2
  Bill of materials / OS packages      NOT ASSESSED         -  —
  Source code (static analysis)        ASSESSED             2  1/1
  AI/ML systems and model artifacts    ASSESSED             5  1/1
  Secrets in version history           ASSESSED             3  8/8
  AI model runtime behaviour           ASSESSED             4  5/6
  Email authentication                 ASSESSED             3  1/1
  Human susceptibility                 NOT ASSESSED         -  —
  Detection and response coverage      NOT ASSESSED         -  —

  Not covered by this tool (separate assessment required):
    Network and host infrastructure
    Web application logic and authorisation
    Cloud configuration and IAM
    Identity, directory and privilege
    Wireless · Physical security · Mobile applications

Examined 6 of 9 class(es) in this tool's scope; 7 further class(es) are outside it entirely.
Within those examined classes: 18 of 19 unit(s) checked.
Findings: 29 — this count reflects ONLY the classes marked ASSESSED or PARTIAL above.
```

"29 findings" and "examined 6 of 9 classes, with 7 more entirely out of scope"
tell very different stories. The ledger is embedded in the client report, so
the reader gets both.

### Four rules that keep it honest rather than flattering

**1. It lists classes ColdLight *cannot* assess.** Showing only our own classes
would let "all classes assessed" read as full coverage when nobody tested the
network, the web app, cloud config or identity. Those appear as NOT ASSESSED
with "requires a separate assessment", because the reader needs the shape of
the whole problem, not just our slice.

**2. Emitting Sigma rules is not detection coverage.** Shipping a rule says
nothing about whether anyone would have *noticed*. Detection reports NOT
ASSESSED — pointing at `detect validate` — even when the rules were written.
A tool that counted its own deliverables as coverage would be grading its own
homework.

**3. It declares ColdLight' own blind spots.** The code scan reads the working
tree, so "secrets in version history" is listed as a class we could cover but
don't. A key committed and later deleted is still in history and still
compromised; that belongs in the ledger, not buried in documentation.

**4. No figure can be read as overall coverage.** An early version printed
`units 4/4 (100%)` next to a 3-of-7 assessment — precisely the false
reassurance this feature exists to prevent, introduced by me while building
it. The percentage is gone; the unit figure is explicitly scoped ("within
those examined classes"), and the finding count carries "reflects ONLY the
classes marked ASSESSED". A test asserts no bare percentage is ever printed.

### Statuses

| Status | Meaning |
|--------|---------|
| `ASSESSED` | Examined; the finding count is meaningful |
| `PARTIAL` | Examined, but incompletely — e.g. 45 SBOM components unmappable, or DKIM inconclusive. The ratio shows the gap |
| `NOT ASSESSED` | **Unknown, not clean.** Nobody looked, with the reason stated |
| `FAILED` | The stage ran and broke; the error is carried through |

`PARTIAL` and `FAILED` are what most tools quietly fold into "clean".

## Verifiable results: `coldlight attest`

A pentest report today is a PDF emailed around with no integrity at all.
Nothing stops a finding being deleted between the assessor sending it and the
board reading it, and nothing records which tool and which inputs produced it.

```bash
coldlight attest create assessment/ --sign-with gpg --key you@example.com
coldlight attest verify assessment/ --require-signature
```

```
contents  : OK — 7 file(s) match their recorded digest
signature : OK (gpg) Good signature from "ColdLight Test Key <test@invalid>"
scope     : 2 of 7 class(es) examined; NOT assessed: sbom, detection, …

VERIFIED: contents match and the signature is valid.
Note: a valid signature only means something if you obtained the signer's
public key through a channel you trust. ColdLight does not establish that.
```

### It attests to scope, not just content

This is the part that makes it worth doing. Signing *"here are 17 findings"*
is near-worthless if the recipient cannot tell whether 17 came from assessing
everything or from assessing one directory. The statement therefore binds:

- the SHA-256 of every **report** file (the subjects),
- the SHA-256 of every **scan artifact** behind it (the inputs),
- the **assurance ledger** — which classes were examined, which were partial,
  and which nobody looked at.

So a recipient can verify the claim *and its limits*. It's an
[in-toto](https://in-toto.io) Statement, not an invented format.

### No cryptography is implemented here

Hand-rolled signature code is how a tool ends up looking verified while being
forgeable. ColdLight canonicalises the document and hashes files with stdlib
`hashlib`; **signing and verification are delegated** to GnuPG or OpenSSL.
Private key material is never read, held or logged — only a key id or path is
passed through, and passphrases are left to `gpg-agent` or to `openssl`'s own
`-passin env:VAR` (the variable *name* reaches the command line, never the
value). A test asserts no passphrase flag appears in any constructed command.

An `hmac` backend exists for the one case it suits — a party checking its own
artifact hasn't been altered in storage — and says plainly in its own output
that it is symmetric and therefore proves nothing to a third party.

### Proven against actual tampering

Verified by hand with a throwaway GnuPG key, not just asserted:

| Attack | Result |
|--------|--------|
| Delete a finding from `report.md` | `ALTERED: report.md` → **exit 1** |
| Also rewrite `attestation.json` so the digest matches | digests pass, `BAD signature` → **exit 1** |
| Leave everything alone | `VERIFIED` → exit 0 |

That second row found a real bug in my own CLI: it exited **0** on a BAD
signature unless `--require-signature` was passed. An invalid signature is
evidence of tampering and is categorically different from *no* signature
(where you simply cannot tell). It now always fails, flags or not, and there's
a regression test for it.

> **Trust model, stated plainly:** a detached signature only means something
> if the recipient already holds your public key through a channel they trust.
> ColdLight does not distribute keys and cannot establish that for you. An
> unverifiable signature is worse than none, so the tool says so in its own
> output rather than implying more assurance than it provides.

## Quick start

```bash
# 1. (optional) scaffold a fresh campaign config
python coldlight.py new october-drop        # -> campaigns/october-drop/campaign.toml

# 2. edit campaign.toml — set engagement_id, authorization_reference, sponsor, lure

# 3. check it
python coldlight.py validate campaign.toml

# 4. build: validates, compiles the exe, and stages the USB — one command
python coldlight.py build campaign.toml
```

`build` produces:
- `dist/coldlight_awareness.exe` — the payload, with your campaign **baked in**.
- `USB_stage/` — copy the **contents** onto each stick: the exe (renamed to your
  lure), `autorun.inf`, the rendered training page, and a "found this USB" note.

### Useful build flags

| Flag | Effect |
|------|--------|
| `--console` | Keep a console window (handy while testing; omit for deployment). |
| `--icon path.ico` | Give the exe a believable icon. |
| `--output DIR` | Where to put `dist/` and `USB_stage/` (default: current dir). |
| `--allow-placeholders` | Build even with `CHANGE-ME` values (lab/testing only). |
| `--stage-config` | Also drop an editable `campaign.json` on the USB (overrides the baked config without a rebuild; breaks the lure's cover, so off by default). |

## How config flows

You edit **`campaign.toml`** → `build` validates it, bakes a JSON copy **inside**
the exe, and renders the training page. At runtime the payload resolves config in
this order:

1. `campaign.json` next to the exe (if you used `--stage-config`) — tweak without rebuilding,
2. the **baked** copy inside the exe,
3. safe built-in defaults.

Nothing is hardcoded anymore; one `campaign.toml` is the single source of truth.

## ⚠️ Authorization

`validate` / `build` **block** on placeholder values: `engagement_id` and
`authorization_reference` must be real before a production build. Keep them honest
— they're shown to the person and make the test auditable. Only test people and
machines you're explicitly authorized to, under a signed RoE.

## Reality check: autorun is dead

`autorun.inf` will **not** auto-execute. Microsoft disabled AutoRun for USB /
removable drives in 2011 (Windows 7+). It's included only as a label. A modern
USB-drop test succeeds through social engineering — a believable lure filename
and icon the person chooses to open.

## Requirements / build notes

- Python 3.11+ (uses stdlib `tomllib`); `pip install -r requirements-dev.txt` for
  `build` (PyInstaller) and the test suite (pytest).
- **Code-sign the exe** with your org's cert before deploying — unsigned, it trips
  SmartScreen/AV, which confounds "did the person run it" with "did AV catch it"
  (signing for trust, not evasion):
  ```bash
  python coldlight.py sign dist\coldlight_awareness.exe --thumbprint <SHA1>   # cert in store
  # or a PFX, password from an env var (never on the command line):
  set COLDLIGHT_PFX_PASS=...  &  python coldlight.py sign dist\coldlight_awareness.exe --pfx c.pfx --password-env COLDLIGHT_PFX_PASS
  ```
  Add `--dry-run` to preview the exact `signtool` command. Needs `signtool.exe`
  from the Windows SDK (auto-located, or pass `--signtool`).

## Delivery vectors

The USB drop is the default, but the same collector + training back a second,
link-based vector:

- **Click-tracking landing page** (`GET /land?c=<campaign>&t=<tag>`): put the link
  in a simulated phishing email or on a flyer. Visiting it records an awareness
  "click" (vector `link`, de-duped per visitor via a cookie) and shows the training
  page. It **never asks for credentials** — no form, no password field.
- **QR-code drop**: a printable poster whose QR points at that landing URL.

```bash
python coldlight.py qr --base-url https://host:8000/land --campaign <id> --tag lobby-poster --out poster.svg
```

Hits from every vector land in the same DB; `report` and the dashboard break them
down **by vector** (and keep excluded/safe-listed hits separate).

## Collect results

Each run appends a JSON line to `coldlight_awareness_hits.jsonl` (on the USB and in
`%TEMP%`) and, if a collector is configured, POSTs the same record home. Two ways
to turn that into numbers:

**Offline — from collected USB sticks (no server):**
```bash
python coldlight.py report --ingest D:\coldlight_awareness_hits.jsonl E:\...jsonl --csv report.csv
```
De-dupes by run id into `hits.db`, prints a summary (totals, unique hosts/users,
per-engagement, runs-by-day), and optionally exports a CSV for leadership.

**Live — central collector + dashboard:**
```bash
# generate a token, set the SAME value in campaign.toml ([collector] url + token), rebuild
python -c "import secrets; print(secrets.token_urlsafe(24))"
python coldlight.py serve --token <token>        # dashboard at http://127.0.0.1:8000/
```
The collector is **token-authenticated** (ingest *and* stats), rate-limited, and
caps body size. It binds to `127.0.0.1` by default — if you expose it, put it
behind HTTPS / a reverse proxy. The dashboard asks for the token and shows live
tiles, a runs-by-day chart, and a per-engagement table.

Recorded per hit: engagement id, run id, UTC timestamp, hostname, username, OS,
and the path it ran from. Nothing more — keep it that way, and purge it when the
campaign closes.

## Opt-out safe-list & data retention

**Safe-list (opt-out / sensitive identities)** — exclude people who opted out,
executives, or service accounts. Case-insensitive globs, `host:` / `user:` scoped
or bare (matches either):

- *Payload-side* (`[safelist] patterns` in `campaign.toml`): a matching host/user
  makes the payload **suppress itself** — no log, no beacon, no message. These
  patterns are baked onto the USB, so prefer role/prefix patterns over full names.
- *Collector-side* (`serve --safelist file.txt`, one pattern per line): matching
  hits are stored flagged **excluded** and left out of the headline stats. Kept on
  your server, not the USB — the privacy-preferred option.

**Data retention** — purge PII when the campaign closes. `purge` is a **dry-run by
default**; nothing is deleted without `--yes`.

```bash
python coldlight.py purge --db hits.db --older-than 30         # dry-run count
python coldlight.py purge --db hits.db --older-than 30 --yes   # actually delete
python coldlight.py purge --db hits.db --engagement OLD-ID --yes
python coldlight.py serve --token <t> --retention-days 30      # auto-purge while serving
```

## Vulnerability assessment

Find real, provable weaknesses — and leave with a prioritised fix list. Every
command here is **read-only**: it identifies and reports. It never fetches,
generates or runs exploit code.

### What a finding tells you

Every finding answers three questions, not just the first:

```
[KEV] CRITICAL CVE-2021-44228  org.apache.logging.log4j:log4j-core 2.14.1 (Maven)
    Remote code injection in Log4j
    cvss 10.0 | epss 1.000 (very high) | CWE-20 Improper Input Validation
    PUBLIC EXPLOIT: 3 listed on Exploit-DB, earliest 2021-12-14
        EDB-50592 (remote/java) https://www.exploit-db.com/exploits/50592
    likely patch: https://github.com/apache/logging-log4j2/pull/608
    KNOWN EXPLOITED (CISA KEV) -- due 2021-12-24  [used in ransomware campaigns]
```

**How urgent** — CVSS says how bad it would be; **EPSS** says how likely anyone
is to try. The spread is what CVSS hides: Log4Shell scores `1.000`, while a
jinja2 CVE rated HIGH scores `0.004`. Both look alike by severity alone.

**What it actually is** — `--verbose` prints the full advisory writeup plus the
weakness itself, from the bundled CWE catalogue:

```
    weakness: Improper Input Validation
      Input is used without checking that it is the expected type, length,
      format or range...
      fix: Validate against an allow-list of acceptable values, not a deny-list.
      fix: Check type, length, format and range at the trust boundary.
```

**How to fix it** — the fixed versions, plus the reference that is *actually*
the patch. NVD tags references `Patch` / `Exploit` / `Vendor Advisory` and OSV
types them `FIX` / `ADVISORY` / `WEB`; those labels used to be discarded,
leaving 70 anonymous URLs.

`patch:` means the database said so. `likely patch:` means we inferred it from
the URL shape — which is needed because **GHSA advisories in OSV never emit
`FIX`**, so for Maven, npm and NuGet the fix commit would otherwise sit
unlabelled among the rest. The inference deliberately excludes advisory-database
repos: a pull request against `github/advisory-database` changes the *advisory*,
not the vulnerable code, and a naive heuristic calls it the patch.

### Where each severity comes from

Severities in this framework have three different kinds of authority, and a
report printing "4 critical" without saying which is which invites the reader
to treat an opinion as a measurement. Every finding now records its source:

| Source | Meaning | Measurement? |
|--------|---------|--------------|
| `nvd-cvss` | NIST CVSS base severity | **yes** |
| `osv-database` | the advisory database's own rating (e.g. GHSA curator) | **yes** |
| `cisa-kev` | raised to critical *by ColdLight* because CISA lists it exploited | no |
| `coldlight-rule` | our code-scanner rule table | no |
| `coldlight-judgement` | our assessment (email posture, awareness) | no |
| `unscored` | nobody published a severity | no |

The report shows the split rather than a single total:

```
| Severity | Findings | Measured | Assessed by ColdLight |
|----------|----------|----------|--------------------|
| Critical | 1        | 0        | 1                  |
| High     | 2        | 1        | 1                  |

**1 of 6** severities are an external measurement; the remaining **5** are
ColdLight' own assessment.
```

On that run the only Critical was *entirely* our judgement — a hardcoded-key
rule — with no measured backing at all. Worth knowing before it reaches a
board pack. Each finding is labelled too: *Critical (ColdLight rule table)* reads
very differently from *Critical (NVD CVSS base score)*.

Three details that keep it honest:

- **The KEV promotion is attributed to us.** `apply_kev` raises an unscored
  finding to CRITICAL because CISA confirms exploitation. Nothing published
  that rating, so it is recorded as `cisa-kev` and never counted as measured.
- **GHSA ratings are not CVSS.** A curator's qualitative rating is a different
  authority from a NIST base score, so they are separate sources even though
  both are external.
- **A grouped finding drawing on several authorities reports `mixed sources`**
  rather than silently adopting whichever came first.

`coldlight_codescan` and `coldlight_mail` declare their source as a literal rather
than importing the constants, so a test asserts those literals are members of
the canonical set — the two cannot drift apart.

### Exploit-DB: metadata, never exploit code

The published `files_exploits.csv` index maps CVE → EDB-ID, type, platform,
date and a **verified** flag. That a verified public exploit has existed since
2021-12-14 is prioritisation data. The CSV's `file` column — the path to the
exploit body — is never read, and a test asserts it does not appear in output.

Enrichment is on by default (`--no-exploit-intel` to skip). EPSS is one batched
request; the Exploit-DB index is ~10 MB fetched once and cached for a week as a
reduced CVE map.

### Official sources

| Source | What it gives you |
|--------|-------------------|
| **NVD** (NIST / MITRE CVE) | Canonical CVE records: description, CVSS score + vector, CWE class, references. |
| **OSV.dev** (Google) | Which advisories affect an exact open-source package version, and the version that fixes it. |
| **CISA KEV** | The CVEs *known to be exploited in the wild*. This is the signal that turns a 60-CVE list into a "fix these three first" list. |
| **Exploit-DB** | Reference **links only**, as carried in the upstream advisories — ColdLight never downloads or runs an exploit body. |

### Dependency scanning

```bash
python coldlight.py scan deps .                         # walk the repo, check every pinned dep
python coldlight.py scan deps . --json findings.json    # machine-readable report
python coldlight.py scan deps . --fail-on high          # exit 1 if anything >= HIGH (CI gate)
python coldlight.py scan deps . --enrich                # fill in CVSS/CWE from NVD (slower)
```

Understands `requirements*.txt`, `package-lock.json`, `package.json`, `go.mod`
and `Cargo.lock`; skips vendored trees (`node_modules`, `.venv`, …) and de-dupes
the same package across manifests. Findings sort **KEV first**, then by severity,
then CVSS. Output shows the fixed version for each one.

### SBOM scanning (assess something you didn't build)

A manifest scan needs the source tree. An SBOM scan doesn't — so you can assess
a **vendor container, a third-party appliance, or a binary a supplier shipped
you**, using the inventory they (or `syft`/`trivy`/`cdxgen`) already produced.

```bash
python coldlight.py scan sbom bom.json                    # CycloneDX or SPDX
python coldlight.py scan sbom bom.json --inventory-only   # summarise, no network
python coldlight.py scan sbom bom.json --fail-on critical --json out.json
```

Reads **CycloneDX JSON** (1.2–1.6, including nested components), **SPDX JSON**
(2.x) and **SPDX tag-value**. Components are identified by their
[purl](https://github.com/package-url/purl-spec), mapped to the right OSV
ecosystem: PyPI (PEP 503 normalised), npm (incl. `@scope/name`), Maven
(`group:artifact`), Go (module path, `v` stripped), crates.io, RubyGems, NuGet,
Packagist, Hex, Pub, Conan, CRAN, Swift, Hackage — plus OS packages for
**Debian, Ubuntu, Alpine, Red Hat, Rocky and AlmaLinux**.

> **Anything it can't map is reported as NOT CHECKED, with a reason — never
> silently dropped.** This is the whole safety design. Container SBOMs are
> mostly OS packages, and OSV needs the distro in the ecosystem string
> (`Debian:11`, `Alpine:v3.18`). A component quietly omitted would read as
> "clean" when it was never assessed. A known unknown is safe; a silent gap is
> not. Typical skip reasons: no purl in the SBOM, an OS package with no
> resolvable distro version, or an unsupported purl type (e.g. `docker`).

Verified behaviour worth knowing: OSV **validates** the ecosystem and returns
HTTP 400 for an unrecognised one, which ColdLight records as an error. So a bad
mapping surfaces loudly rather than as a false negative.

### VEX: say which findings actually apply

A scan says "your product contains log4j 2.14.1, which has Log4Shell." That is
not the same as "your product is exploitable." **VEX** (Vulnerability
Exploitability eXchange) is the machine-readable way to state the difference —
for answering a supplier's questionnaire, or telling your own customers.

```bash
python coldlight.py vex init bom.json --out triage.json \
    --product-name vendor-appliance --product-version 4.2.1 \
    --product-purl pkg:oci/vendor-appliance@4.2.1 --config campaign.toml
# ... record your decisions in triage.json ...
python coldlight.py vex validate triage.json
python coldlight.py vex emit triage.json --format openvex --out vex.json
```

**It is deliberately two-step, because VEX assertions are human judgements.**
No scanner can know whether vulnerable code is reachable in your build, or
whether a mitigating control already covers it. So `init` produces a triage
file with every finding `under_investigation` — an honest, conformant starting
state — sorted **KEV first** so the actively-exploited ones get triaged first.
`--from-json report.json` reuses a saved scan instead of re-querying OSV.

Then you record decisions, one of four statuses:

| Status | Requires | Means |
|--------|----------|-------|
| `under_investigation` | — | Triage in progress (the default) |
| `not_affected` | a **justification** or impact statement | Present but not exploitable here |
| `affected` | an **action_statement** | Exploitable; here's what to do |
| `fixed` | fix versions | Already remediated |

`not_affected` takes one of the five standard VEX justifications:
`component_not_present`, `vulnerable_code_not_present`,
`vulnerable_code_not_in_execute_path`,
`vulnerable_code_cannot_be_controlled_by_adversary`,
`inline_mitigations_already_exist`.

**The emitters refuse to produce non-conformant VEX.** A bare `not_affected`
with no justification, or `affected` with no action statement, is an error
naming the statement — consumers reject such documents, and a VEX nobody can
consume is worse than no VEX at all.

### Three formats, one decision

`--format openvex | cyclonedx | csaf`. OpenVEX and CSAF share the VEX core
vocabulary; CycloneDX has its own. ColdLight keeps one canonical model and maps
outward, so a decision recorded once comes out correct everywhere:

| Your decision | OpenVEX | CycloneDX | CSAF 2.0 |
|---|---|---|---|
| `not_affected` + `vulnerable_code_not_in_execute_path` | same, verbatim | `state: not_affected`, `justification: code_not_reachable` | `known_not_affected` + `flags[].label` |
| `affected` | `status: affected` + action statement | `state: exploitable`, `response: [update]` | `known_affected` + `remediations[]` |
| `fixed` | `status: fixed` | `state: resolved` | `fixed` |

Details that matter for real consumers: CycloneDX output includes the
referenced components with matching `bom-ref`s, so no `affects[].ref`
dangles; CSAF models each component via a `default_component_of`
relationship and points statements at the **relationship** product id, which
is the correct granularity for "this library as shipped inside this product."

### Source-code scanning

```bash
python coldlight.py scan code .                         # insecure patterns + leaked secrets
python coldlight.py scan code . --fail-on critical      # CI gate
python coldlight.py scan code . --exclude "tests/*"     # skip paths (repeatable)
```

Pattern rules mapped to CWE: hardcoded credentials and cloud keys (CWE-798),
command injection sinks (CWE-78), `eval`/`exec` (CWE-95), unsafe deserialisation
(CWE-502), SQL string interpolation (CWE-89), disabled TLS verification
(CWE-295), weak hashing/RNG (CWE-327/338), XSS sinks (CWE-79), and debug or
wildcard-host exposure (CWE-489/16). Each finding carries a remediation line.

**Discovered secrets are redacted in the report** (`password = "***REDACTED***"`),
so the output can be shared without leaking the credential it just found.

Suppress a reviewed false positive with a trailing `# nosec` or
`# coldlight:ignore` **on the flagged line**, and leave a comment saying why — see
`coldlight_report.py` for worked examples (f-string SQL where the interpolated text
is a fixed constant and all values are bound parameters).

It's a fast pattern-based first pass, not a replacement for semgrep or CodeQL —
confirm findings in context and pair it with a full SAST engine for depth.

### Secrets in git history

```bash
python coldlight.py scan history .                    # all reachable history
python coldlight.py scan history . --removed-only     # only what `scan code` can't see
python coldlight.py scan history . --fail-on critical # CI gate
python coldlight.py scan history . --since "1 year ago"
```

`scan code` reads the working tree, which answers the less interesting
question. The dangerous case is the key someone committed, noticed, deleted in
the next commit, and considered dealt with. It is still in the object store,
still in every clone, and still valid.

Every finding says which of the two it is:

| State | Meaning |
| --- | --- |
| **still in HEAD** | `scan code` already found it — same problem, reported once in each place |
| **GONE FROM HEAD** | the interesting one. Someone believes this was fixed; deleting the line changed nothing |

On a throwaway repo with one key committed-then-deleted and one still live,
`scan code` reports **1** finding and `scan history` reports **2** — the
difference is the whole point of the command.

The same credential re-added across several commits collapses into one finding
with a commit count and the commit that introduced it, attributed to its
author so you know who to ask about rotation.

**A shallow clone is reported NOT ASSESSED and exits 2.** This matters more
than it sounds: CI checks out with `fetch-depth: 1` by default, which is
exactly where you would run this, and a truncated history finds almost nothing
and looks identical to a clean result. So it refuses rather than reassures.
Use `fetch-depth: 0`, or `--allow-shallow` to scan the little there is (still
reported as incomplete).

Secrets are redacted for display and reduced to a SHA-256 fingerprint for
grouping, so the report can say "the same key appears in 14 commits" without
the report becoming another place the key is written down. Verified: no raw
credential appears in any generated artifact.

#### Rotation is the fix, not history rewriting

The remediation text says so plainly, because the instinct is backwards.
`git filter-repo` changes what *future* clones get, needs every collaborator
to re-clone, and does nothing about copies already taken. Rotating the
credential is the only step that helps.

#### What it does not cover

Reachable history — what someone with a clone can recover. Not dangling
objects from amended or rebased commits, and not the local reflog: neither
travels with a clone, so neither is what an outsider gets. And whether a
credential was ever rotated cannot be determined from the repository, so a
finding means *recoverable*, not necessarily still valid.

### AI/ML security assessment

```bash
python coldlight.py scan ai .                      # AI/LLM code + model artifacts
python coldlight.py scan ai . --fail-on high       # CI gate
python coldlight.py scan ai . --exclude "tests/*"  # skip paths (repeatable)
```

20 rules mapped to the **OWASP Top 10 for LLM Applications (2025)**, to CWE,
and — where the identifier is certain — to **MITRE ATLAS**:

| What it finds | OWASP | CWE |
| --- | --- | --- |
| `torch.load` without `weights_only=True`; pickle/joblib/dill model loads; `trust_remote_code=True`; Keras without `safe_mode`; unpinned hub revisions | LLM03 Supply Chain | 502, 494 |
| Model output passed to `eval`, a shell, SQL or `innerHTML` | LLM05 Improper Output Handling | 95, 78, 89, 79 |
| Prompts built from request data; retrieved documents concatenated into the prompt | LLM01 Prompt Injection, LLM08 | 74 |
| Agents handed shell/REPL tools; tool calls auto-approved | LLM06 Excessive Agency | 269 |
| Provider API keys in source; prompts and completions written to logs | LLM02 Sensitive Information Disclosure | 798, 312 |
| Model calls with no token ceiling | LLM10 Unbounded Consumption | 400 |

Most of these are not novel AI problems — they are classic weaknesses wearing
new clothes, which is exactly why they get missed. Loading a pickle-based model
is CWE-502 deserialisation; `trust_remote_code=True` is documented behaviour
rather than a bug, routinely set by someone copying a quickstart; passing model
output to a shell is the same injection it always was, with the model as a new
untrusted source.

Each provider's keys get their own rule, so the report names the right one.
Anthropic keys also begin `sk-`, and a rule that lumps them in with OpenAI's
sends you to revoke the wrong credential.

**Model artifacts are classified by reading four bytes** — extension plus
pickle/zip magic — so `.pkl`, `.pt`, `.pth`, `.joblib`, `.h5` and `.ckpt` are
reported as code-executing formats, and `.safetensors`, `.onnx`, `.gguf` and
`.tflite` as safe. It never calls `pickle.load` or `torch.load`, because
deserialising an untrusted model *is* the vulnerability being reported. A test
enforces that by failing the suite if any unpickler is called during a scan.

Notebooks are scanned including **stored cell output** — a committed `.ipynb`
with a key printed in a result leaks it just as surely as source does.

#### What this does not tell you

Static review only. **No model is prompted, probed or adversarially tested**, so
susceptibility to prompt injection, jailbreak or data extraction is *not*
established by this scan. The report and the assurance ledger both say so, in
those words, rather than letting a quiet scan imply a robust model. Pair it with
a live evaluation harness for that.

### CVE lookup & triage

```bash
python coldlight.py cve CVE-2021-44228          # one CVE: CVSS, CWE, refs, KEV status
python coldlight.py vulns "apache struts"       # keyword-search NVD
python coldlight.py vulns "fortinet" --kev-only # only what's actively exploited
python coldlight.py kev --search fortinet       # browse the KEV catalog directly
```

### Notes

- **No API key needed.** Optionally set `NVD_API_KEY` to lift NVD's rate limit
  (~5 req/30s → ~50 req/30s); ColdLight throttles itself either way.
- The KEV catalog is cached for 24h (`--refresh` to force; `COLDLIGHT_CACHE` to
  relocate).
- **TLS verification is always on and cannot be disabled.** If a lookup fails
  with a certificate error, that's usually a stale CA bundle on *your* machine,
  not a bad server — point ColdLight at a current one with
  `COLDLIGHT_CA_BUNDLE=/path/cacert.pem` (or `pip install certifi`).

### One trust store, shared by every connection

`coldlight_trust.py` owns the CA-bundle precedence and the verifying context, and
every module that makes a network call imports it: vulnerability lookups, the
Exploit-DB index, email auditing, `probe`, and the preflight itself.

It did not start that way. The context lived inside `coldlight_vulnintel`, so it
was effectively that module's private property — whatever imported it got the
configured trust store, and whatever didn't quietly used the system default.
`coldlight_mail` was in the second group, which meant `COLDLIGHT_CA_BUNDLE` fixed
your NVD and OSV lookups and did **nothing** for `mail audit`, with no way to
tell which of your connections honoured it.

A trust store that applies to only some of a tool's connections is worse than
one that applies to none, because it looks like it is working.

The guard against a recurrence is structural, because nothing else would have
caught it — every individual call site looked correct; only the *set* of them
was wrong. The suite parses every `coldlight*.py` module and fails if any
`urlopen` is called without the shared context:

```
urlopen without context=ssl_context() -- these calls use the system trust
store instead of the configured one: ['coldlight_mail.py:125']
```

One module is exempt, and the exemption has to state why: `coldlight_awareness.py`
is the awareness payload. It runs on a *found USB on someone else's machine*,
where the assessor's `COLDLIGHT_CA_BUNDLE` is neither present nor relevant, and
it's frozen into an exe carrying only `coldlight_config` beside it. It gets the
stdlib default context, which verifies normally. A test asserts that the
payload still makes a TLS call at all, so a dead exemption cannot sit there
covering nothing.

Honest consequence: `mail audit` now **fails** on a machine where
`COLDLIGHT_CA_BUNDLE` points at an unusable bundle, where before it quietly
worked. That is the correct behaviour — the alternative is an email audit
whose transport security differs from the rest of the tool for no stated
reason — but it is a behaviour change, and `coldlight doctor` tells you which
bundle is in use before you hit it.

## Scope: the gate on anything active

Everything above reads files, manifests, public advisory databases and DNS.
None of it reaches into a system under assessment. `coldlight probe` does, so it
does not run on a flag — it runs against a declared, signed-off, time-bounded
scope, or it refuses.

```bash
coldlight scope --init scope.toml                     # commented template
coldlight scope scope.toml                            # validate and show it
coldlight scope scope.toml --target https://app.corp.example.com
```

```toml
[scope]
authorization_reference = "TICKET-4417"    # a placeholder here is refused
authorized_by = "Jane Smith, CISO"
valid_from  = "2026-11-18"
valid_until = "2026-12-02"

targets  = ["https://staging.corp.example.com/api", "http://localhost:8000"]
excluded = ["https://staging.corp.example.com/api/admin"]
```

Four properties make it a gate rather than a decoration:

**Deny by default.** No scope file, an empty `targets`, or a host nobody
listed — all refused. "I forgot to configure it" must never mean the same
thing as "everything is permitted".

**Exclusions always win,** whatever the file order. A carve-out a wildcard
could override would not be a carve-out, so `/api/admin` stays refused while
`/api` is in scope.

**Wildcards are bounded.** `*`, `*.com` and `*.co.uk` are refused when the
file loads, not when you run something — a scope that authorises most of the
internet is a configuration mistake, and the time to say so is beforehand.
`*.dev.example.com` covers subdomains only; list the apex separately if you
mean it too.

**Every decision is recorded,** refusals included, and reaches the report.
Afterwards you can show exactly what was authorised, what was turned down, and
under which reference.

Path rules match at separator boundaries, so `/api` does not authorise
`/apikeys`.

## Live susceptibility probing: `coldlight probe`

`scan ai` finds prompt-injection *sinks* in source and states plainly that it
cannot tell you whether the model falls for anything. This asks the running
system.

```bash
coldlight probe --scope scope.toml --dry-run    # print the payloads, send nothing
coldlight probe --scope scope.toml --json probe.json --fail-on high
```

Each probe puts a harmless, uniquely-tagged instruction into a channel where
untrusted data would arrive, then looks for the tag in the reply:

| Probe | Channel | What it demonstrates |
| --- | --- | --- |
| `CANARY-INDIRECT-DOCUMENT` | retrieved document | content the model merely *read* was treated as instruction |
| `CANARY-INDIRECT-HTML-COMMENT` | retrieved document | instructions in markup no human reader ever sees |
| `CANARY-INDIRECT-TOOL-RESULT` | tool result | the agent trusts whatever its tools hand back |
| `CANARY-DELIMITER-ESCAPE` | retrieved document | the delimiter around untrusted text can be closed from inside it |
| `CANARY-DIRECT-INSTRUCTION` | user input | the system prompt is advisory, not enforced |
| `CANARY-SYSTEM-PROMPT-LEAK` | system prompt | a marker *you* planted in it comes back to the user |

The instruction asks for exactly one thing: emit a meaningless token. The
token proves the mechanism — nothing harmful has to be requested to establish
that a channel is injectable.

### What it deliberately is not

There is no jailbreak corpus here, and the probe set is **not loadable from a
file**: a tool that runs arbitrary payloads from a config is an attack tool
regardless of what the config happens to hold today. Nothing attempts to
elicit harmful content, bypass a safety policy, extract real data, or optimise
an adversarial suffix. These are canaries, not exploits.

### Echo is not susceptibility

Plenty of chat endpoints return the submitted message alongside the reply, and
a token found in an echoed request proves nothing. So every probe also carries
a phrase from its own instruction; if that phrase comes back, the result is
INCONCLUSIVE with a note to point `response_path` at the model's reply. Run
against an endpoint that just echoes its input, the probe reports **0
susceptible, 6 inconclusive** — without that check it would have reported six
HIGH findings against something that runs no model at all.

### Three outcomes, and the third is not a pass

`SUSCEPTIBLE` / `RESISTED` / `INCONCLUSIVE`. An unreachable endpoint, an error
status or an unreadable reply is inconclusive, never resisted — a failed
request is not a model that held the line. If *no* probe reaches a verdict the
run exits 2 and the ledger records FAILED, because a run that established
nothing is not a clean one.

A clean run means little by design: six canaries resisted is six canaries
resisted. Susceptibility is cheap to demonstrate and impossible to disprove
this way, so the report says that rather than implying robustness.

## Email authentication: *why* the phishing worked

A click rate tells you people are human. This tells you whether an attacker
could put **your** domain in the `From:` line — which turns "31% clicked" from
a finding about people into a finding about a control you can fix this week.

```bash
python coldlight.py mail audit example.com
python coldlight.py mail audit example.com --records-only   # just the DNS to publish
python coldlight.py mail audit example.com --fail-on high --json out.json
```

### The misconception this exists to correct

**SPF does not stop spoofing of the visible `From:` header.** SPF
authenticates the SMTP envelope sender (`MAIL FROM` / Return-Path), which the
recipient never sees. A domain can publish a flawless `v=spf1 ... -all` and
still be trivially spoofable in the only field a human reads. Only **DMARC**
requires alignment with the visible `From:`, so DMARC policy alone decides
spoofability — and that is exactly how the tool scores it.

| DMARC | `spoofable` | `protection_level` |
|-------|-------------|--------------------|
| absent, or `p=none` | yes | `none` |
| `p=quarantine` | yes — accepted and filed to spam, not refused | `partial` |
| `p=reject; pct<100` | yes — enforced on only part of your mail | `partial` |
| `p=reject` at 100% | no | `full` |

Quarantine counts as spoofable on purpose: the forgery is still *accepted*,
recipients do read spam, and the spec leaves quarantine handling to the
receiver. `protection_level` carries the three-way nuance so a bool can't
over-reassure.

### What it checks

- **SPF** — qualifier (`-all` / `~all` / `?all` / `+all` / absent), and the
  **10-DNS-lookup limit counted across the full recursive expansion**. Over the
  limit, RFC 7208 says permerror, which commonly **fails open** — so the record
  you think protects you may never be evaluated. A top-level record can look
  short and still blow the limit through its includes, which is why the count
  follows every `include:`.
- **DMARC** — policy, subdomain policy (`sp=`), enforcement percentage,
  alignment modes, and whether `rua=` reporting exists (without it, moving to
  enforcement is guesswork). `p=reject` with `sp=none` is flagged: subdomains
  stay spoofable, and attackers prefer them precisely because they look related.
- **DKIM** — probes ~37 common selectors, parses the key and derives RSA
  modulus size by **walking the DER**, not guessing from base64 length.
- **MTA-STS / TLS-RPT / DNSSEC / MX** — inbound transport hardening, plus
  RFC 7505 null-MX detection.

Then it prints the exact DNS records to publish.

### Accuracy guardrails

These exist because a report full of false findings gets ignored:

- **A negative DKIM result is reported as inconclusive, never as "DKIM
  missing."** Selectors are arbitrary strings and cannot be enumerated from
  DNS. Use `--selector` with the value from a real `DKIM-Signature` header.
- **Wildcard `*._domainkey` is detected with a control probe.** Some zones
  answer for *any* selector; without the control every probe looks like a hit
  and you get dozens of bogus entries instead of one real observation.
- **Null MX (`0 .`) suppresses inbound-transport findings.** A domain that
  declares it accepts no mail should not be told to deploy MTA-STS.
- **A revoked DKIM selector (`p=` empty) is INFO, not a vulnerability** — it's
  the RFC 6376 way to retire a key, so normal rotation isn't flagged as a flaw.
- **`--no-fetch` never manufactures a finding.** If the MTA-STS policy wasn't
  fetched, the report says so instead of claiming it's unusable.

### Passive by design

Everything here reads **public DNS** over DNS-over-HTTPS (Cloudflare, falling
back to Google). The only request that touches the target's own infrastructure
is the well-known MTA-STS policy file over HTTPS, which `--no-fetch` disables.
Nothing is sent, probed or exploited — this is the same data any receiving mail
server consults.

## Purple team: did anyone *notice*?

The awareness test tells you how many people ran the file. This tells you
whether anyone would have **caught** it. Those are different findings, and the
second is usually the more actionable: *"31% ran it and nothing alerted"* is a
very different report from *"31% ran it and we caught every one."*

```bash
python coldlight.py detect map                              # what this exercises, per ATT&CK
python coldlight.py detect rules --out sigma/ --config campaign.toml
python coldlight.py detect navigator --out attack_layer.json
python coldlight.py detect checklist --config campaign.toml --out checklist.md
python coldlight.py detect validate --db hits.db --out worksheet.md
```

### What it maps to

| Technique | Vector | What ColdLight actually does |
|-----------|--------|---------------------------|
| **T1091** Replication Through Removable Media | USB | A binary is carried in on removable media and run. *No* self-copying, *no* autorun abuse. |
| **T1204.002** User Execution: Malicious File | USB | The user is socially engineered into double-clicking an unsigned exe. |
| **T1566.002** Phishing: Spearphishing Link | link, QR | A tracked link records the click. No form, no credential prompt. |
| **T1071.001** Application Layer Protocol: Web Protocols | USB | One authenticated HTTPS POST home — looks like beaconing to a sensor. One-way: no tasking. |

`detect map` prints the full mapping with, for each vector, the telemetry to
check and the known gaps. It's explicit that ColdLight covers only the **entry**
behaviour — but that's the point: the behavioural indicator (unsigned binary
from removable media, then egress) is identical whether the payload is benign
or not, which is exactly what makes it usable for detection engineering.

### Sigma rules

`detect rules` writes rules you can convert with `sigma convert -t <backend>`:

- Executable launched from removable media by the shell (T1091 + T1204.002)
- Outbound connection from a binary on removable media (T1091 + T1071.001) —
  execution *plus* egress is much higher fidelity than either alone
- Removable device arrival (Security 6416; DriverFrameworks 2003/2100/2102)

With `--config`, it also emits **campaign-pinned** rules: your exact lure
filename and collector host, so the blue team can hunt this specific engagement
and separate test activity from real activity.

### Closing the loop

`detect validate` is the part that makes this worth doing. ColdLight already knows
which host, which user and which second each run happened — precisely the pivot
a defender needs. It emits a per-hit worksheet with a ±5-minute SIEM search
window and vector-specific things to look for, and asks for one of three
outcomes per hit:

| Outcome | Meaning | Action |
|---------|---------|--------|
| **Alerted** | An analyst was notified | Confirm it reached a human, and how fast |
| **Logged, not alerted** | Telemetry exists, no rule fired | Highest-value gap — write/tune the rule |
| **No telemetry** | Nothing recorded it | Fix *collection* before detection |

> ⚠️ Run `detect checklist` **before** the campaign. Several of the most useful
> USB log sources (removable-storage auditing, DriverFrameworks-UserMode) are
> **off by default** — if you don't enable them first, the test will look like a
> detection failure when it's really a logging gap.

For technique depth beyond the entry behaviour, drive the same technique IDs
with **Atomic Red Team**; ColdLight covers delivery and user execution only.

## Baseline / diff: only what's new

`--fail-on high` is unadoptable on its own. Point it at any real codebase with
a backlog and it fails on commit one, so nobody leaves it enabled. A baseline
fixes that: accept the backlog once, then the gate trips only on findings that
appeared **since**.

```bash
# 1. the gate fails on the existing backlog -- correct, but unusable in CI
python coldlight.py scan code . --fail-on high              # exit 1

# 2. accept the current state (commit the file)
python coldlight.py scan code . --baseline .coldlight/baseline.json --update-baseline

# 3. same code, same gate -- now passes
python coldlight.py scan code . --baseline .coldlight/baseline.json --fail-on high

#    3 finding(s) total
#      3 in baseline (accepted 2026-11-17)
#      0 new since baseline                              # exit 0
```

Later, after someone adds an `eval()` and deletes an md5 call:

```
3 finding(s) total
  2 in baseline (accepted 2026-11-17)
  1 NEW since baseline:
    HIGH      Dynamic code evaluation (eval/exec) — app.py:29

  1 RESOLVED since baseline (no longer present):
    MEDIUM    Weak hash algorithm (MD5/SHA1) — app.py:15

FAIL: 1 new finding(s) at or above HIGH.
```

Available on `scan deps`, `scan sbom`, `scan code` and `mail audit`. One
baseline file can hold all four — `--update-baseline` for one source leaves
the others intact.

### Fingerprinting (why it actually holds up)

A baseline is worthless if irrelevant changes break the match, so identity
deliberately excludes volatile detail:

| Source | Keyed on | Deliberately **not** keyed on |
|--------|----------|-------------------------------|
| Code | rule + file + whitespace-normalised snippet | **line number** — it shifts whenever anything above it is edited, which would make every refactor look like a wave of new findings |
| Dependencies | vulnerability + ecosystem + package | **installed version** — a bump that doesn't fix the issue is the same finding; one that does fix it disappears on its own |
| Email | domain + check + title | — |

Paths are normalised to posix and made relative to the scan root, so CI and a
developer laptop agree. In the example above, the two surviving findings moved
down 13 lines and still matched.

Identical occurrences of one pattern in one file share a fingerprint, so
counts are tracked per fingerprint: accepting one occurrence does not license
three — an increase is reported as new.

**Known limitation, asserted in a test rather than glossed over:**
normalisation absorbs indentation and trailing space, but adding space inside
an expression (`f(cmd)` → `f( cmd )`) changes the snippet and therefore the
fingerprint. Stripping all whitespace would risk merging genuinely different
code, so that reformat shows up as resolved + new — noisy, but it never
silently hides a finding.

The baseline file is designed to be **committed and reviewed**: keys are
readable and namespaced (`code:CMD-OS-SYSTEM@app.py#ca1df150b8`), entries are
sorted for clean diffs, each carries a human label, severity and `first_seen`,
and `first_seen` is preserved across updates so accepting new findings doesn't
rewrite the history of old ones.

## The deliverable

Five modules produce findings. This turns them into one report.

```bash
# produce the inputs
python coldlight.py scan deps .          --json vuln.json
python coldlight.py scan code . --exclude "tests/*" --json code.json
python coldlight.py mail audit corp.example.com   --json mail.json

# assemble
python coldlight.py engagement \
    --vuln vuln.json --code code.json --mail mail.json \
    --hits hits.db --vex triage.json --config campaign.toml \
    --client "Acme Corp" --title "Acme Corp — Security Assessment" \
    --period "2026-11-01 to 2026-11-14" --scope "acme-portal 2.3.0" \
    --format html --out report.html
```

`--format html` (self-contained, dark-mode aware, print-ready), `md`, or
`json` for a pipeline.

### Findings are triaged, not dumped

A dependency scan can return 60 CVEs. Sixty standalone findings is a report
that gets skimmed and ignored, so it's edited the way an analyst would:

- **Known-exploited (CISA KEV) and critical items are promoted** to their own
  findings — they're the action items, and they sort to the top.
- **The long tail is grouped** into one finding carrying the full list in its
  evidence. Nothing is lost; nothing important is buried.
- **Code findings group by rule**, not per line: *"Hardcoded credential
  assignment (3 occurrences)"* with the locations as evidence, capped with a
  tail note.
- **VEX decisions are honoured.** Anything you marked `not_affected` or
  `fixed` moves to Appendix A with its justification instead of padding the
  finding count.

The summary still reports the honest total: *"18 findings covering 32
underlying items."*

### It states what it did not establish

Appendix B is assembled from the modules themselves, not boilerplate:

- *No exploitation was attempted* — findings record a weakness, which is not
  proven exploitability. This is always present.
- SBOM components that couldn't be mapped to vulnerability data, carried
  through as UNKNOWN rather than clean.
- Static analysis is pattern-based, so absence of a finding isn't proof of
  absence of a flaw.
- DKIM probes that came back inconclusive.
- Whether anyone *detected* the awareness activity — unmeasured unless you ran
  `detect validate`.

### Other properties worth knowing

Secret redaction survives into the deliverable: a hardcoded key found by
`scan code` appears as `***REDACTED***`, verified by a test asserting the raw
value never reaches the report. All content is HTML-escaped, since findings
carry snippets from scanned source. The awareness finding's remediation leads
with a **technical control** (execution policy on removable media) rather than
only training, and the executive summary is explicit that the conclusion is
not that individuals failed.

## After the test

Report **aggregate** numbers to leadership; treat individuals supportively (the
message already tells people they're not in trouble) and pair results with short
follow-up training.

## Guardrails (the line this kit does not cross)

ColdLight **identifies and reports**. It does not weaponize. Concretely:

| ✅ In scope | ❌ Out of scope |
|------------|----------------|
| Measuring who runs an unknown file / clicks an unknown link | Payload execution, shellcode, droppers |
| Finding known-vulnerable dependencies and insecure code | Fetching or running exploit code / PoCs |
| CVE, CVSS, CWE and KEV intelligence from official feeds | Auto-exploitation ("scan → pop the box") |
| Reporting findings with remediation guidance | Credential capture, persistence, privilege escalation, lateral movement |
| Code-signing for *trust* (so AV doesn't confound results) | AV/EDR evasion, obfuscation, self-propagation |

If a real engagement needs the right-hand column, that's a different,
separately-scoped and separately-authorized effort using purpose-built,
access-controlled tooling (Metasploit, Sliver, Mythic, Caldera) — not this kit.
For validating detections, pair ColdLight findings with Atomic Red Team.

## Self-test

```bash
python coldlight_awareness.py --dry-run     # prints the record + config source, no side effects
python coldlight.py validate campaign.toml  # config check
```

## Tests

```bash
pip install ".[dev]"
pytest
```
1172 tests covering config loading/validation, the reporting layer (dedup,
metrics, export), the collector (auth, rate/size limits, dedup, dashboard), the
payload, the signing helper, the vulnerability-intelligence layer (manifest
parsers, NVD/OSV parsing, KEV prioritisation, CI gating, TLS trust), SBOM
ingest (purl parsing, every ecosystem mapping, CycloneDX/SPDX/tag-value, and
that unmappable components are reported rather than dropped), VEX (every
status/justification mapping in all three formats, the conformance rules, and
the triage round-trip), email authentication (SPF lookup counting through
nested includes and loops, every DMARC policy combination, DER key sizing,
wildcard and null-MX handling), the code scanner (every rule, secret
redaction, suppression, tree-walking), the purple-team layer (ATT&CK mapping,
Sigma generation, worksheet rendering) the report assembler (grouping, VEX
suppression, limitation collection, HTML escaping and self-containment) and
the baseline layer (fingerprint stability across line shifts, reformatting and
version bumps; occurrence counting; cross-source merging) and the CLI itself
(exit codes, and that every command fails with an explanation rather than a
traceback when run outside a checkout or without an optional dependency).

**No network access required** — the vuln-intel tests stub the HTTP layer, so
the suite is deterministic and runs offline.

The Sigma emitter is hand-rolled (no pyyaml at runtime), so the tests parse
every generated rule with a **real** YAML parser and assert the regexes and
Windows paths survive quoting intact — a mangled regex silently matches
nothing, which looks like "no detections" rather than a broken rule. Those
tests skip cleanly if pyyaml isn't installed.

## Roadmap

Config + CLI: **done**. Secured reporting + dashboard: **done**. Test suite +
code-signing helper: **done**. Opt-out/safe-list + data retention: **done**.
Delivery vectors (QR drop + click-tracking landing page): **done**.
Vulnerability assessment (dependency + code scanning, NVD/OSV/KEV intelligence):
**done**. Purple-team layer (ATT&CK mapping, Sigma rules, Navigator layer,
per-hit detection validation): **done**. SBOM ingest (CycloneDX + SPDX, 20
ecosystems): **done**. VEX output (OpenVEX + CycloneDX + CSAF 2.0, with
conformance validation): **done**. Email authentication posture
(SPF/DKIM/DMARC/MTA-STS/TLS-RPT/DNSSEC): **done**. Engagement report
(aggregated HTML/Markdown/JSON deliverable): **done**. Baseline/diff mode
(report only new findings; resolved tracking): **done**. Packaging + CI
(installable `coldlight`, GitHub Actions, changelog): **done**. Single-file build
(one dependency-free `.py`, verified byte-identical): **done**. One-command
orchestrator (`assess`, profile-driven, honest about failed stages): **done**.
Assurance ledger (per-class coverage, including what the tool cannot
assess): **done**. Signed attestations (in-toto, delegated signing, tamper
detection): **done**.

Possible next steps: add a `LICENSE` (none yet — needed before
distributing); carrying VEX triage decisions forward between scans the
way the baseline now carries scan findings; recording detection-validation
outcomes back into the DB so coverage trends across campaigns; a scope file
(authorized domains/CIDRs) enforced by any module that reaches a remote
target; packaging (`pyproject.toml`) so it installs as `coldlight` on PATH.
