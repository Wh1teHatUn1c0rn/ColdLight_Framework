# Changelog

All notable changes to ColdLight. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [1.4.1] — 2026-11-18

### Fixed
- **`COLDLIGHT_CA_BUNDLE` applied to only some of ColdLight.** The TLS context lived
  inside `coldlight_vulnintel`, which made it that module's private property:
  anything importing it got the configured trust store, anything else used the
  system default. `coldlight_mail` never imported it, so the variable fixed NVD
  and OSV lookups and silently did nothing for `mail audit` or the MTA-STS
  policy fetch — with no way for an operator to tell which of their
  connections honoured it. A trust store that covers part of a tool is worse
  than one that covers none, because it looks like it is working.
  - Found by `coldlight doctor`: under a deliberately broken bundle every feed
    probe failed while DNS kept answering, which is only possible if DNS is
    using a different trust store.
- `check_doh` blamed the network for what was really a certificate problem.
  Now that DNS shares the one context, a bad CA bundle takes the resolvers
  down with everything else, and the old remedy ("DNS-over-HTTPS is blocked
  on this network") would have sent someone to argue with their network team
  about a file on their own disk.

### Added
- **`coldlight_trust.py`** — the shared trust store: CA-bundle precedence, the
  verifying context, and no option to weaken it. Small enough that every
  network-using module can import it without pulling anything else in, and
  with no fallback path, because a module that cannot import it has no TLS at
  all and should say so rather than silently reaching for another store.
  - `ca_bundle_source()` and `ignored_ca_bundle_vars()` so the doctor asks
    which bundle is in use instead of re-deriving the precedence rules and
    risking a report that describes a trust store other than the real one.
  - `reset()` for tests that change the CA environment; the context is
    memoised, so without it such a test is answered by one an earlier test
    built.
- **A structural guard against recurrence.** Nothing else would have caught
  this: every individual call site looked correct and only the set of them was
  wrong. The suite now parses every `coldlight*.py` module and fails if any
  `urlopen` is called without the shared context. Verified by reverting the
  fix: it names `coldlight_mail.py:125`.
- `coldlight_awareness.py` is the one exemption, and the test requires a stated
  reason: the payload runs on a found USB on someone else's machine, where the
  assessor's bundle is neither present nor relevant, and it is frozen with
  only `coldlight_config` beside it. A further test asserts the payload still
  makes a TLS call, so a dead exemption cannot sit there covering nothing.

### Changed
- `coldlight_canary` and `coldlight_exploitintel` now take the context from
  `coldlight_trust`. Canary's private `_ssl_context()` fallback copy is gone —
  a second copy of the fallback was the start of the same drift.
- `coldlight_vulnintel` re-exports `ca_bundle` and `ssl_context`, which were part
  of its published surface. Its `_ssl_ctx` global is **removed** rather than
  left behind: a dead cache would mean anything resetting it had no effect
  while appearing to, which is the same trap in a new place. A test asserts
  it is gone.
- **Behaviour change:** `mail audit` now fails on a machine whose
  `COLDLIGHT_CA_BUNDLE` points at an unusable bundle, where it previously worked
  by using a different trust store. `coldlight doctor` reports which bundle is
  in use before you hit it.

## [1.4.0] — 2026-10-01

### Added
- **`coldlight doctor` — preflight the external dependencies** (`coldlight_doctor.py`).
  ColdLight is stdlib-only at runtime but not self-contained: it leans on a `git`
  binary, a current CA bundle, two DNS-over-HTTPS resolvers, five vulnerability
  and exploit feeds, and optionally GnuPG or OpenSSL. Until now a missing one surfaced
  mid-engagement as a confusing error from whichever stage needed it first.
  - The report is organised around **commands, not binaries**: `git is not on
    PATH -> scan history will not run`, with a closing list of every command
    that will not work on this machine.
  - Checks the Python floor, `tomllib`, the `ssl` module and its OpenSSL
    version, `sqlite3` (by opening a database, not just importing), the active
    trust store, `certifi`, `git`, GnuPG, OpenSSL, `signtool`, PyInstaller,
    `qrcode`, the feed cache, all five feeds and both DoH resolvers.
  - Exit codes: **0** everything checked is healthy, **1** some commands will
    not work, **2** ColdLight cannot run here at all.
  - `--profile assessment.toml` narrows the run to what that engagement needs
    — nineteen checks become six — and names the stages that have no external
    dependency rather than omitting them.
  - `--offline` for local checks only, `--json` for an artifact carrying the
    Python, platform and ColdLight version as run provenance.
- **Every probe goes through the real code path.** TLS uses
  `coldlight_vulnintel.ssl_context()` and DNS uses `coldlight_mail.doh_query()`, the
  actual functions. A preflight that opened its own socket with its own trust
  store could report a healthy machine while every scan fails.
- **A `DEGRADED` state distinct from a failure.** A host answering `HTTP 403`
  proved DNS, TCP and TLS all work and is merely rate-limiting; reporting that
  as a connectivity failure would send someone to debug the wrong layer. A
  fallback mirror in use, and one blocked DoH resolver out of two, are also
  degraded rather than broken.
- **DNS is one check covering both resolvers.** `mail audit` tries them in
  order and needs one, so per-resolver checks would condemn the command on a
  blocked Cloudflare. Which resolver is blocked still appears in the detail.
- **`assess` now opens with this check**, scoped to the stages the profile
  configures, naming the stages that will fail before the scanning starts. It
  reports and continues rather than gating: aborting would discard the stages
  that would have worked. `--no-preflight` skips it.
- The probes carry **nothing about the engagement** — a constant public
  package name for OSV, a well-known CVE id for EPSS, `example.com` for DNS.
  A test fails if a future change makes a probe read from its input. The two
  multi-megabyte feeds are probed with `HEAD`.
- CI asserts that an offline run reports every external service as NOT
  CHECKED and never as `ok`, so "nobody looked" cannot decay into "clean".

### Fixed
- `check_ca_bundle` surfaces a misconfiguration that previously failed
  silently: `ca_bundle()` ignores `COLDLIGHT_CA_BUNDLE` and `SSL_CERT_FILE` when
  they point at a file that is not there and falls back without a word, so
  someone who set the variable to fix a verification error never learned it
  had no effect. It is now reported as DEGRADED, naming the ignored path.
- `openssl --version` is a usage error on OpenSSL 1.x and LibreSSL. The first
  live run reported `OpenSSL (CLI)  ok  Invalid command '--version'` — a
  usage error printed where a version belonged, which would have read as a
  healthy check. The probe now uses `openssl version`.
- The test for a missing optional dependency patched `shutil.which`, which
  PyInstaller and `qrcode` do not use — they are located with
  `importlib.util.find_spec` — so both reported `ok` under a test asserting
  they were absent. Split into one test per lookup mechanism.
- `coldlight_vulnintel` memoises its SSL context, so the trust-store tests reset
  it around each case; otherwise a test that changes the CA environment is
  answered by a context whichever test ran first had already built.

### Changed
- `tests/test_doctor.py` assembles the forbidden TLS phrases at runtime rather
  than writing them out, because spelled literally they are exactly what
  `scan code` flags as CWE-295 and this project scans its own tree in CI.

## [1.3.0] — 2026-08-04

### Added
- **`scan history` — secrets committed to git history** (`coldlight_history.py`).
  Closes the gap the assurance ledger has been carrying as an explicit NOT
  ASSESSED row since it was written: `scan code` reads the working tree, so a
  credential committed and then deleted was invisible to it while remaining
  in the object store and in every clone.
  - Every finding states whether the secret is **still in HEAD** (also
    reported by `scan code`) or **gone from HEAD but still recoverable** —
    the second being the one most likely to be believed fixed. `--removed-only`
    shows just those.
  - The same credential re-added across commits collapses into one finding
    with a commit count, the introducing commit and its author.
  - Secret rules are reused from `scan code` and `scan ai` (every rule marked
    `redact`), so a new provider token added there is covered here for free.
  - Remediation says rotation is the fix: rewriting history changes only what
    future clones get and does nothing about copies already taken.
  - `--max-commits`, `--since`, `--exclude`, `--baseline` and `--fail-on`,
    with bounds on diff volume and wall-clock time so a large repository
    cannot turn into an unbounded read.
- **A shallow clone is reported NOT ASSESSED and exits 2.** CI checks out
  with `fetch-depth: 1` by default, which is exactly where this would run,
  and a truncated history finds almost nothing while looking identical to a
  clean result. `--allow-shallow` scans anyway and is still reported as
  incomplete.
- Secrets are redacted for display and reduced to a SHA-256 fingerprint for
  grouping, so the report never becomes another copy of the credential.
- `history` baseline source, an `engagement --history` input with its own
  report category, and an `assess` `[stages.history]` stage.

### Changed
- The `secrets_history` ledger class is no longer a declared blind spot. Its
  note now describes what the check establishes and what stays out of reach
  (dangling objects, the local reflog, whether the key was rotated).

### Fixed
- `present_in_head` was computed against a pooled set of fingerprints, so the
  same credential appearing in two files marked the deleted copy as still
  live — hiding the exact finding the module exists to surface. It is now
  resolved per file.
- `build_ledger` appended a second `secrets_history` entry instead of
  replacing the old blind-spot one, so the printed ledger listed the class
  twice, once ASSESSED and once NOT ASSESSED. Per-class tests passed
  throughout because the lookup returns the first match; there is now a test
  asserting every class appears exactly once.
- Removed an unreachable duplicate branch in `coldlight_baseline.label_for`.

## [1.2.0] — 2026-06-10

### Added
- **`coldlight scope` — the authorization gate** (`coldlight_scope.py`). Nothing
  active runs without a declared, in-date, signed-off scope file. Deny by
  default: no file, an empty target list, or an unlisted host are all refused,
  so a missing configuration can never read as blanket permission.
  - Exclusions always win, whatever the file order — a carve-out a wildcard
    could override would not be a carve-out.
  - Wildcards are bounded at load time: `*`, `*.com` and `*.co.uk` are
    refused before anything runs, as are CIDR blocks. `*.x.example.com`
    covers subdomains only.
  - Path rules match at separator boundaries, so `/api` does not authorise
    `/apikeys`.
  - Authorization expires, and every decision — refusals included — is
    recorded for the report.
- **`coldlight probe` — benign injection susceptibility probing**
  (`coldlight_canary.py`). Six canaries place a harmless, uniquely-tagged
  instruction in a channel where untrusted data would arrive (retrieved
  document, HTML comment, tool result, delimiter escape, direct user input)
  and look for the tag in the reply. System-prompt leakage is detected via a
  marker the operator plants in their own prompt, so nothing guesses at the
  real text.
  - `--dry-run` prints every payload and sends nothing. Request header values
    are never shown or written to the report.
  - Three outcomes, and INCONCLUSIVE is not a pass: an unreachable endpoint,
    an error status or an unreadable reply never counts as RESISTED. A run
    where no probe reached a verdict exits 2 and records FAILED.
- **`ai_runtime` class in the assurance ledger** ("AI model runtime
  behaviour"), NOT ASSESSED until a probe actually runs — so a clean static
  scan can no longer imply a model that was tested. The `ai_ml` note now
  points at it instead of asserting susceptibility is unestablished.
- `engagement --probe` and an `assess` `[stages.probe]` stage, with findings
  in their own "AI runtime behaviour (observed)" category: these describe
  something the assessment watched happen, not a pattern it recognised.

### Scope
- Unchanged: ColdLight identifies and reports. The probe set is fixed, benign and
  deliberately **not loadable from a file** — a tool that runs arbitrary
  payloads from a config is an attack tool whatever the config holds. No
  jailbreak corpus, no harmful-content elicitation, no data-extraction
  attempt, no adversarial-suffix optimisation.

### Fixed
- Two `assess` probe-stage tests dialled a dead port and blocked for 20
  seconds each; they now stub the transport, since they test how the stage
  handles a no-verdict run rather than the network.

## [1.1.0] — 2026-05-01

### Added
- **`scan ai` — AI/ML security assessment** (`coldlight_aisec.py`). 20 static
  rules mapped to the OWASP Top 10 for LLM Applications (2025), to CWE, and —
  where the identifier is certain — to MITRE ATLAS. Covers unsafe model
  deserialisation (`torch.load` without `weights_only`, pickle/joblib/dill,
  Keras without `safe_mode`), `trust_remote_code=True`, unpinned hub
  revisions, model output reaching `eval`/shell/SQL/`innerHTML`, prompts built
  from request data, RAG context concatenation, agents given shell or REPL
  tools, auto-approved tool calls, provider credentials in source, prompt and
  completion logging, and missing token ceilings.
- Model artifacts are classified by extension **plus four magic bytes**:
  `.pkl`/`.pt`/`.pth`/`.joblib`/`.h5`/`.ckpt` are reported as code-executing
  formats, `.safetensors`/`.onnx`/`.gguf`/`.tflite` as safe. Nothing is ever
  deserialised — doing so is the vulnerability being reported — and a test
  fails the suite if any unpickler is called during a scan.
- Notebook scanning covers **stored cell output** as well as source: a key
  printed into a committed `.ipynb` result leaks like any other.
- `ai_ml` class in the assurance ledger, so a repository full of `torch.load`
  calls no longer reads as assessed-and-clean when no AI scan was run. Its
  note states that no model was probed, prompted or adversarially tested.
- `assess` gained an `ai` stage (`[stages.ai]`, `--ai DIR`), and `engagement`
  an `--ai` input with its own report category carrying OWASP/ATLAS references.
- `--exclude` on `assess` now applies to the AI scan as well as the code scan;
  `[stages.ai]` inherits the code stage's exclude list when it sets none.

### Fixed
- `AI-SECRET-OPENAI` also matched Anthropic keys, which begin `sk-` too, so a
  leaked Anthropic key was reported under the wrong provider — pointing the
  reader at the wrong console to revoke it.
- `AI-OUTPUT-TO-SQL` missed the two commonest real forms: a placeholder inside
  a quoted SQL literal (`WHERE body = '{response}'`) and plain concatenation.
  The quoting that makes it injectable was what stopped the rule matching.
  It now requires a SQL verb in the string, which also keeps it off innocent
  f-strings such as `query(f"_dmarc.{domain}")`.
- `AI-AGENT-SHELL-TOOL` and `AI-AGENT-AUTO-APPROVE` only matched assignments,
  missing the dict and YAML forms (`"auto_approve": True`) that agent
  configuration is actually written in.

### Scope
- Unchanged: ColdLight identifies and reports. This module adds no jailbreak or
  adversarial-prompt corpora, probes no live model, and loads no artifact.

## [1.0.0] — 2025-11-23

First consolidated release. ColdLight is a **benign** security assessment
framework: every capability identifies and reports, none exploits.

### Awareness testing
- Config-driven campaigns (`campaign.toml`) shared by CLI and payload, with
  validation that blocks placeholder engagement/authorization values.
- Benign USB-drop payload: records the run, shows a training message,
  optionally beacons. No persistence, shellcode, credential access or evasion.
- Token-authenticated collection server with dashboard, rate limiting and a
  body-size cap; click-tracking landing page with no credential fields.
- QR-poster and tracked-link vectors; results broken down by vector.
- Opt-out safe-list (payload- and collector-side) and data-retention purging.
- Authenticode signing helper — for trust, so AV does not confound results.

### Vulnerability assessment
- `scan deps`: requirements/package-lock/package.json/go.mod/Cargo.lock
  against OSV.dev, cross-referenced with the CISA KEV catalog.
- `scan sbom`: CycloneDX JSON, SPDX JSON and SPDX tag-value; purl mapping for
  20 ecosystems including Debian/Ubuntu/Alpine/RHEL/Rocky/AlmaLinux.
  Components that cannot be mapped are reported as NOT CHECKED, never dropped.
- `scan code`: ~25 CWE-mapped rules with discovered secrets redacted in the
  report, `# nosec` suppression and `--exclude` path filtering.
- `cve`, `vulns`, `kev`: NVD and CISA KEV lookups. TLS verification is always
  on and cannot be disabled.

### Email authentication
- `mail audit`: SPF (including the 10-DNS-lookup limit counted across the full
  recursive expansion), DMARC, DKIM, MTA-STS, TLS-RPT and DNSSEC over
  DNS-over-HTTPS. Spoofability is scored on DMARC alone, because SPF does not
  constrain the visible `From:` header.

### Purple team
- `detect map`: what the test exercises, mapped to MITRE ATT&CK (T1091,
  T1204.002, T1566.002, T1071.001), with telemetry and known gaps.
- `detect rules`: Sigma rules, optionally pinned to a campaign's lure and
  collector host.
- `detect navigator`: ATT&CK Navigator layer.
- `detect validate`: per-hit worksheet with SIEM search windows, scoring each
  hit as alerted / logged-not-alerted / no telemetry.

### VEX
- `vex init` / `validate` / `emit`: triage-then-emit workflow producing
  OpenVEX, CycloneDX VEX or CSAF 2.0 from one canonical model. Emitters refuse
  non-conformant output (`not_affected` with no justification, `affected` with
  no action statement).

### Severity provenance
- Every finding records where its severity came from: `nvd-cvss`,
  `osv-database`, `cisa-kev`, `coldlight-rule`, `coldlight-judgement` or `unscored`.
  Previously a NIST CVSS 9.8 and a ColdLight opinion were indistinguishable in a
  report.
- The report shows measured-vs-assessed per severity, a breakdown by source,
  and labels each finding; `severities_measured` and
  `severities_assessed_by_coldlight` are in the JSON.
- The KEV promotion (raising an unscored finding to CRITICAL because CISA
  lists it exploited) is attributed to ColdLight, not presented as a published
  rating. GHSA curator ratings are kept distinct from NVD CVSS.
- Grouped dependency findings drawing on several authorities report
  `mixed sources`.
- coldlight_codescan and coldlight_mail declare their source as literals; a test
  asserts those literals are members of the canonical set so the two cannot
  drift.

### Vulnerability detail and remediation
- **Reference classification.** NVD tags and OSV reference types are now read
  instead of discarded, so `patch`, `exploit`, `mitigation` and `advisory`
  links are labelled. Previously the commit that fixed an issue was
  indistinguishable from a blog post among 70 flat URLs.
- A URL-shape heuristic adds `patch_likely` (never `patch`, which is reserved
  for what the database stated), because GHSA advisories in OSV never emit the
  `FIX` type. It excludes advisory-database repositories, whose pull requests
  change the advisory rather than the vulnerable code.
- **Full advisory writeups** are kept. The OSV `details` field was truncated to
  400 characters; a Log4Shell record carries 3014.
- **CWE enrichment** (`coldlight_cwe.py`): 36 weaknesses with MITRE names,
  descriptions and concrete mitigations, bundled so it needs no network. A test
  asserts every CWE the code scanner emits has an entry.
- **EPSS** (FIRST.org): probability of exploitation in the next 30 days,
  alongside the binary KEV flag.
- **Exploit-DB metadata** from the published CSV index: EDB-ID, type, platform,
  date and verified flag. The index only -- never an exploit body.

### Verifiable results
- `attest create` / `attest verify`: an in-toto Statement binding the report
  files, every scan artifact behind them, AND the assurance ledger — so the
  attestation covers scope, not just content.
- No cryptography is implemented in ColdLight. Signing and verification are
  delegated to GnuPG or OpenSSL; key material is never read or logged, and
  passphrases are left to gpg-agent or `openssl -passin env:VAR`. A symmetric
  `hmac` backend exists and declares that it proves nothing to a third party.
- Verified against real tampering with a throwaway key: editing the report is
  caught by digest mismatch, and additionally rewriting the attestation to
  match is caught by the signature.
- Fixed while testing: `attest verify` exited 0 on a BAD signature unless
  `--require-signature` was passed. An invalid signature is evidence of
  tampering, distinct from no signature at all, and now always fails.

### Assurance ledger
- `assurance`: a per-class record of what was assessed, what was only
  partially assessed, and what nobody looked at — embedded in the report and
  printed after `assess`. `--require-complete` gates on it.
- It lists check classes ColdLight **cannot** assess (network, web application,
  cloud configuration, identity, wireless, physical, mobile) so their absence
  is explicit rather than implied by a short findings list.
- Emitting Sigma rules does not count as detection coverage; only recorded
  outcomes would. ColdLight' own blind spot (version-history secrets) is declared
  in the ledger too.
- No figure is presented that could be read as overall coverage: the unit
  ratio is explicitly scoped to the examined classes, and a test asserts no
  bare percentage is printed.

### One-command assessment
- `assess`: runs every configured stage from an `assessment.toml` profile
  (`assess --init` scaffolds one), writes a JSON artifact per stage so every
  number in the report is traceable, applies baselines, builds the report in
  any of html/md/json, and exits on the worst gate. CLI flags override the
  profile, so the file is optional.
- **A failed stage is never reported as a clean stage.** No stage can abort
  the run; each failure is recorded with its error, carried into the report's
  limitations as "treat that area as UNKNOWN, not as clean", and reflected in
  the exit code. Exit `2` (incomplete) deliberately outranks exit `1` (gate
  tripped), because totals from a run that did not finish cannot be trusted.
- Each stage clears its own stale artifacts first, so a failed stage cannot
  leave a previous run's JSON in the output directory to be picked up later.
- `run.json` records stage statuses, errors, artifact paths, the gate result
  and `incomplete`, making the output directory self-describing.

### Reporting
- `engagement`: aggregates every source into one HTML / Markdown / JSON
  deliverable. KEV and critical items are promoted; the long tail is grouped;
  VEX-cleared records move to an appendix. States what was not assessed.
- `--baseline` / `--update-baseline` on `scan deps`, `scan sbom`, `scan code`
  and `mail audit`: report only findings new since the accepted baseline, plus
  what was resolved. Fingerprints survive line shifts, reformatting and
  version bumps.

### Packaging
- Installable as `coldlight` (`pip install .`); `coldlight --version`.
- Runtime is stdlib-only. Extras: `[build]` (PyInstaller), `[qr]` (qrcode),
  `[certs]` (certifi), `[dev]` (pytest, pyyaml).
- **Single-file build** (`python build_bundle.py --verify`): one ~161 KiB
  dependency-free `.py` you can drop on any box with Python 3.11+. Modules are
  embedded zlib+base64 and served to the import system by a meta-path finder,
  so sources are never rewritten. `--verify` proves extraction is
  byte-identical to the repository and that the extracted sources pass the
  whole suite; `--extract` writes them back out for audit. The campaign
  templates are embedded too, so `new` and `build` work from the standalone
  file — which the wheel cannot do.
- 781 tests, no network access required — upstream HTTP is stubbed.

### Notes
- `new` and `build` need the campaign templates that ship beside the modules,
  so run those two from a checkout rather than an installed wheel. Both now
  fail or warn explicitly instead of degrading silently.
- No `LICENSE` file yet — add one before distributing.

### Fixed during development
- **Dependency findings were double-counted.** OSV returns both a GHSA and a
  PYSEC advisory for one CVE; both normalised to the same identifier, so every
  affected CVE appeared twice and the severity-less record manufactured a
  spurious "unknown severity" bucket. Records are now merged, keeping the best
  severity, score and the union of aliases, fixes and references.
- Git commit hashes from OSV `GIT` ranges were presented as fixed versions.
- Oversized POSTs to the collector returned a connection reset instead of a
  clean 413, because the body was never drained before the socket closed.
- The SQL-injection rule matched any `query(f"...")` call, flagging DNS
  lookups; both branches now require actual SQL in the string.
- Email audit: wildcard `*._domainkey` zones made every probed DKIM selector
  appear to exist (now detected with a control probe); null MX (`0 .`) domains
  were told to deploy inbound TLS controls; revoked selectors were rated
  MEDIUM rather than informational; and `--no-fetch` reported the MTA-STS
  policy as unusable without ever looking at it.
- TLS verification against NVD failed on a host carrying an expired
  cross-signed root; ColdLight now uses a configurable current CA bundle
  (`COLDLIGHT_CA_BUNDLE`, `SSL_CERT_FILE`, or certifi) and never disables
  verification.
