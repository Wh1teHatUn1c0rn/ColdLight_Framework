# Changelog

All notable changes to ColdLight. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **Every advisory in a report is one click from the database record it came
  from.** Grouped dependency findings used to render as a list of strings with
  the reference discarded: a real scan of a Next.js project put 29 of its 33
  advisories in front of the reader with no link and no indication of which
  component each was about. They are now a table — advisory, what the
  advisory says, installed version, fixed in — linked in both the HTML and
  Markdown reports and carried in full in the JSON.
  - The **"what the advisory says"** column is the database's own sentence,
    quoted rather than parsed. It is the closest thing to "which part of the
    component is affected" that any feed actually states: *in Middleware*,
    *in the Image Optimization API*, *in rewrites*. Deriving a URL path from
    it would be ColdLight asserting framework knowledge no advisory stated,
    and a wrong path in a report is worse than no path.
  - **References keep the kind the intel layer gave them.**
    `coldlight_vulnintel` already separates an advisory the database stated
    from a commit URL this tool recognised, and the report flattened all of
    it into four unlabelled links. A patch link now reads *"Patch (inferred
    from the URL)"*, because presenting it as a fix would promote an
    inference into a statement.
  - **An advisory with no advisory page links the OSV record instead.**
    Measured on that same scan: 11 of 33 advisories name only commits, pull
    requests and mirrors, so a third of the rows would have sent the reader
    to a patch rather than to the finding. The fallback is the record the scan
    actually read, labelled *"OSV record"* and never *"Advisory"* — it is the
    database entry, not the vendor's page.
- **A finding's own advisory page is recognised even when the database never
  typed it as one.** GHSA records in OSV label every reference `WEB` or
  `PACKAGE` and never `ADVISORY`, so on that same Next.js scan 11 of 33
  findings listed their own GitHub security advisory among the unlabelled
  links — the report showed it as *"Reference"* and sorted commit URLs above
  it. `coldlight_vulnintel` now recognises GitHub's two advisory URL shapes
  and emits a new `advisory_likely` kind, which the report prints as
  *"Advisory (inferred from the URL)"*. Measured on that scan: all 11 gain an
  advisory link, and every one of the 33 findings now leads with an advisory
  rather than a patch.
  - **The URL shape alone is not enough.** The page must also name the
    finding — its identifier or one of its aliases. On the same scan 5
    advisory-shaped URLs belong to *other projects* (a `next` finding
    referencing libheif's advisory), and labelling one of those *"Advisory"*
    would have sent the reader to a different component's write-up. The gate
    also refuses the shapes that merely cite an id: a mirror, an NVD record,
    an issue.
  - **It is reported as an inference, not as a statement**, exactly like
    `patch_likely`. The database did not say this page is the advisory; this
    tool read its URL. Printing it as a plain *"Advisory"* would promote a
    recognition into a claim the feed never made.
  - **A recognised advisory suppresses the OSV-record fallback.** That
    fallback exists because a third of findings named no advisory page at
    all; once one is recognised its premise is gone, and the record beside it
    would be a second-best link nobody needs. The fallback stays for findings
    that genuinely have neither.

### Changed
- A grouped finding's per-advisory detail moved from `evidence` to a new
  `rows` field, which the renderers draw as a table. The table is capped at 40
  rows and says so when it truncates (`the first 40 of 60`), because a cap
  that silently showed part of a set as though it were all of it is the same
  failure as a scan that omits what it skipped. The JSON always carries every
  row.

### Fixed
- `Finding.labelled_references` carried a trailing catch-all loop that could
  never run: the main loop already defaults an unclassified URL to `other`,
  which is itself one of the kinds it iterates. Found by a mutation probe that
  proved nothing when the loop was deleted. Removed, with the default
  documented as the mechanism that keeps those links.
- **The indicator-pack tests dated their fixtures on the wrong clock.** The
  helper built dates with `date.today()` — local time — while `coldlight_ioc`
  dates everything in UTC. On a machine east of UTC, in the window between
  local midnight and UTC midnight, local *yesterday* is the scanner's today,
  so a pack the expiry tests meant to have expired was still valid and four
  tests failed. The suite was green when written and red the following night.
  The helper now reads the module's own clock, which cannot drift from it, and
  a test pins that. The CI runners are UTC, where both clocks agree, so
  nothing upstream of a developer's machine could have caught this.

### Not yet
- **A stated advisory that is a database record still outranks the vendor's
  own page.** Where a feed types NVD's `/vuln/detail/CVE-…` page `ADVISORY`,
  that page leads and the vendor's GitHub advisory follows it as the
  inference — visible on 22 of the 33 findings measured. Ordering by *what a
  page is* rather than *who classified it* would fix the sequence, and would
  also mean the report second-guessing its sources. Both links are present
  and correctly labelled, so this is a question of sequence, not accuracy,
  and it is left until there is a reason to prefer one principle over the
  other.
- **Only GitHub's advisory URL shapes are recognised.**
  `/security/advisories/` and `github.com/advisories/` are what the measured
  data contains. Vendor bulletin paths vary too much to pattern-match without
  evidence, and a wrongly labelled advisory is worse than an unlabelled
  reference.

## [1.5.0] — 2026-11-19

### Added
- **`coldlight scan ioc`** and **`coldlight_ioc.py`** — scanning a tree for the
  host-observable markers in a published indicator pack. Three properties
  separate it from grepping a list of strings, and they are the reason it is a
  module rather than a shell loop:
  - **An expired indicator is never a finding.** Packs date their own
    indicators, often in months. Matches past `valid_until` are reported as
    `EXPIRED`, counted apart, excluded from the findings list, and unable to
    fail a `--fail-on` gate. A scanner still matching a string a year after
    its author stopped standing behind it reports its own staleness as
    evidence.
  - **A weak indicator does not alert alone.** Pack authors grade how unique
    each marker is; the common classes are promoted only when something else
    in the same scan also matched, and the promoted finding records which
    indicator corroborated it. One common marker in forty files is still one
    marker — repetition is not corroboration, and an expired indicator cannot
    serve as the second signal.
  - **A stale pack is reported as stale.** Freshness is a coverage claim, not
    a finding, so a pack not refreshed inside the window still produces its
    matches and downgrades the ledger entry to PARTIAL.
- Two load-time refusals, because a warning is not enough when the failure
  mode is a silent clean result: a pack with no source URL or licence does not
  load, and neither does a pack using an indicator kind this version cannot
  evaluate. Skipping an unevaluable class would report a clean scan of a
  surface nothing ever looked at. `KINDS` and `HANDLERS` are held together by
  a structural test so the two cannot drift.
- Ledger class **"Known-tool indicators on disk"**, whose denominator is
  indicators the pack could still vouch for rather than files scanned: `9/10`
  means one indicator had expired and was carried but not used.
- Severity provenance `indicator-pack`, distinct from `coldlight-judgement`
  because the grade is the pack author's, not ours. Deliberately not in
  `MEASURED_SOURCES`: a third party's opinion must not be reported with the
  authority of a CVSS score.
- `examples/ioc/example-pack.toml` documents the format with invented markers.
  Published packs are not vendored — they carry their own licences and expire
  on their authors' schedules, so `--pack` points at a copy you fetched and
  verified.
- A CI step that plants the example pack's lapsed marker in a file and asserts
  it comes back `EXPIRED` with zero findings, end to end through the CLI.
- **Three more indicator surfaces**, bringing `scan ioc` to four:
  - `file_name` — a path or filename, matched against **every** file in the
    tree rather than the ones the source walker opens. A dropped binary has no
    extension that walker would read, so reusing it here would have meant
    reporting no dropped artifact after looking in none of the places one
    lands. Absolute-path indicators work against a relative walk, which is how
    published packs actually write these markers.
  - `listening_port` — a port a configuration file declares, compared as a
    number in a port-like position. A port inside a longer number, or beside a
    key that merely contains the word (`support`, `transport`), is not a
    declaration; nor are the octets of `127.0.0.1:8080`.
  - `container_image` — an image reference a Dockerfile or compose/k8s
    manifest deploys, which is the point of the surface: a registry named in a
    README is prose, not a deployment.
- **Per-surface accounting in the report and the JSON.** A surface no loaded
  indicator covers is reported as `NOT COVERED by these packs`, and one that
  was covered but had nothing to examine reports `0 manifest(s), 1
  indicator(s)`. Those are three different statements and used to be one
  silence. `KIND_SURFACE` is held to `KINDS` by the same structural test that
  holds `HANDLERS` to it.
- A `listening_port` indicator cannot be graded A or B, and a pack that grades
  one that way does not load. Every port is some unrelated software's default,
  so a standalone finding on a two-byte integer would be noise with a severity
  attached. Refused rather than silently downgraded: rewriting a pack author's
  grade would make the report disagree with the pack it cites. `regex` and
  `ignore_case` are refused on that kind too, because an option that silently
  does nothing is worse than one that is rejected.
- Load-time refusal of values that could never match — a port outside
  1–65535, an image reference containing whitespace. Such an indicator loads,
  counts towards the indicators the scan claims to have evaluated, and never
  fires, which inflates the denominator the ledger reports.
- A CI step asserting the corroboration rule across surfaces: a Class C port
  alone stays out of the findings, and is promoted once a second marker
  appears on another surface.
- **Five rules for what a pipeline and a manifest declare**, in
  `scan code`. The scanner has always read `.yml` and `.yaml`, but not one of
  its rules looked at what those files declare:
  - `CI-SECRET-ENCODED` (HIGH, CWE-532) — a build step piping a secret through
    `base64`, `gzip`, `xxd`, `rev` or `openssl enc`. A CI platform masks a
    secret by matching its literal value in the output, so an encoded copy
    prints in full.
  - `CI-ENV-DUMP` (MEDIUM, CWE-532) — `env` or `printenv` piped into one of
    those, which prints every secret injected into the job at once.
  - `CONTAINER-PRIVILEGED` (HIGH, CWE-250) and `CONTAINER-RUNTIME-SOCKET`
    (HIGH, CWE-250) — a privileged container, and the container runtime's
    socket mounted into a workload, which is root on the node.
  - `CONTAINER-HOST-MOUNT` (MEDIUM, CWE-668) — a `hostPath:` key, or a compose
    volume whose host side is a sensitive root. This is how a container reads
    the node's credentials.
  - **A decode flag excludes the line**, and that exclusion is the difference
    between a rule people keep and one they switch off: `base64 -d` pulls a
    stored binary secret INTO a job, which is the ordinary way to carry a GPG
    key, and is the opposite of hiding one on the way out.
  - Scoped to config and shell files on purpose. A Python script declaring a
    privileged container matches the same text and is not reported: the fix
    for a manifest is a manifest change, and these rules point at the file a
    reviewer edits.
  - Both behaviours came from a recent published intrusion, and are
    implemented as generic rules rather than indicators so that they never
    expire and need no intel feed.
- **`coldlight ioc import`** and **`coldlight_stix.py`** — a published STIX
  2.1 bundle becomes an indicator pack, because nobody hand-types a hundred
  indicators. `file:name`, `file:name MATCHES`, `file:hashes.'SHA-256'` and
  `network-traffic:dst_port` are carried; the command then **loads its own
  output back** before reporting success, since a generated pack the scanner
  refuses is worse than an import that failed outright.
  - **The refusal list is the real output.** Every STIX indicator that did not
    become a pack entry is reported with a reason in the operator's terms,
    grouped and counted, and the same list goes into `--json`. A real bundle
    is mostly things this tool cannot see; an importer that silently dropped
    two thirds of one would produce a pack whose clean scan means nothing.
  - **A compound pattern is refused, not narrowed.**
    `[file:name = 'x' AND file:size = 4096]` describes one file and its
    `file:name` half describes every file with that name. Importing the half
    would hand the operator an indicator that looks like the author's and
    matches more than the author said.
  - **A rule in another language is refused, not translated.** Bundles carry
    Sigma, Suricata and YARA patterns, and matching one string out of a
    correlation rule would claim coverage of the whole sequence.
  - **An indicator with no tier and no confidence is refused.** Tier maps to
    the severity the report prints and attributes to the pack author, so
    inventing one puts our guess in their mouth. Where confidence is present,
    the tier is derived from it through a documented table and the entry's
    note records that it was derived.
  - **One default is applied rather than refused**: STIX has no field for the
    uniqueness class, so an entry that states none gets `C` and cannot alert
    alone. `A` would print standalone findings the author never graded as
    distinctive, and refusing would discard most real bundles. Every entry
    that took a default says so in its note, and the summary counts them.
  - **A TLP marking is not read as a licence** — it says who may see the data,
    not the terms of reuse — and a bundle with neither a statement marking nor
    an external reference stops the import with the flag to pass.
  - **`retrieved` is the bundle's own last-modified date** when that is older
    than today, because a pack fetched today from a year-old bundle is a
    year-old pack and the ledger reads that date to decide whether the intel
    is current. It is also clamped to today, so a bundle stamped in the future
    cannot report as fresh.
  - `examples/ioc/example-bundle.json` is a worked bundle: five importable
    indicators across three surfaces and seven refused, one of each class, so
    the example shows the refusals and not only the happy path.
- **A fifth indicator surface, `file_digest`** — the SHA-256 of a file's
  contents, matched against every file under the root:
  - It is the one marker a rename cannot defeat, which is why a published
    pack's strongest Class A entry is usually a digest rather than a path.
  - It is the only surface that reads every byte of every file. A content
    pattern is matched on the first `MAX_FILE_BYTES` and a filename needs no
    read at all, but a truncated hash is not a hash — so this surface hashes
    whole files, including the ones the content surface skips as too large,
    which is routinely where a dropped binary sits.
  - A separate, much higher cap (`MAX_DIGEST_BYTES`) still applies, because
    hashing a multi-gigabyte disk image would stall a scan for nothing. A file
    above it, or one that could not be opened, is counted as **skipped** in
    the surface row and recorded in the errors — never as examined and clean.
  - An MD5 (32 characters) or SHA-1 (40) value does not load, and the refusal
    names the algorithm. Both are still published, this surface computes
    SHA-256, and either would otherwise sit in the indicator count having
    evaluated nothing. A `sha256:` prefix is accepted, since that is how
    registries and STIX patterns write one, and the case is normalised so the
    same digest in capitals is not a second indicator.
  - Unlike a port, a digest may carry **any** uniqueness class. A port graded
    A is refused because no port is distinctive; a digest of a dual-use binary
    is genuinely a common marker, and which it is remains the author's call.
  - Each file is hashed once and the digest looked up, so a pack carrying
    forty digests does not read the tree forty times.
- **An `indicators` stage in `coldlight assess`**, configured by
  `[stages.ioc]` or `--ioc` / `--ioc-pack`, so an indicator scan runs in the
  pipeline and its matches appear in the deliverable:
  - **Either flag alone is refused**, not quietly skipped. A pack with nothing
    to scan and a path with no pack both report the same "no markers found" as
    a clean tree, which is the failure this whole module exists to avoid.
  - **The code stage's exclude list is not inherited**, unlike the AI stage's.
    A pattern added to quieten code-scan noise would also hide a planted
    artifact, so this stage takes its own `exclude` and defaults to none.
  - **A pack whose every indicator has expired fails the stage** — exit 2, the
    ledger class FAILED, the area reported NOT ASSESSED. The artifact is kept,
    because what those indicators would have flagged is worth reading; it is
    just not a result.
  - **No baseline is applied, and the summary says so.** An indicator match is
    not a backlog item to accept and carry, and a reader who configured a
    baseline would otherwise assume this stage honoured it.
  - The gate counts established findings only, as the CLI does: a match
    awaiting corroboration and an expired one may not fail a build.
- `coldlight engagement --ioc`, and `load_ioc_findings` behind it. Indicator
  matches become their own report category with the pack, the uniqueness
  class, the verification level and the tier beside each one; the remediation
  leads with *establish whether this belongs here*, then preserving the host
  before cleaning it, since deleting the artifact destroys the evidence of how
  it arrived. The executive summary states that these are not vulnerabilities
  and are an incident-response question first — the opening paragraph's
  "before the next release cycle" is the wrong clock for a marker on disk.
- Four statements the report now carries that a finding count cannot: which
  surfaces no supplied pack covered (named one by one), the matches awaiting
  corroboration with their ids, the matches whose indicator has expired, and
  which pack was quiet when nothing matched at all. The last of those is
  suppressed when anything did match, including a match that was not promoted:
  "no indicator matched" two lines under "1 match was not established" is a
  contradiction, and a reader who takes away the shorter sentence believes the
  tree was quiet when it was not.
- **A third severity-provenance bucket.** A pack author's tier was not
  measured and is not ColdLight's judgement either, so the findings table
  splits three ways — Measured, Third party, Assessed by ColdLight — and the
  three add up to the finding count. `is_third_party` and
  `Report.third_party_count` are the test seam.
- `coldlight_assurance.STAGE_NAMES`: the assess stage name behind each ledger
  class, in one place, held against `coldlight_assess.STAGES` by a structural
  test. The ledger reads these only when a stage left no artifact, to tell a
  class that FAILED from one nobody ran.
- Tests for the ledger's indicator class, which shipped with the class itself
  and had none: the PARTIAL, ASSESSED, FAILED and NOT ASSESSED paths, and the
  stage-name lookups behind the last two.

### Fixed
- `coldlight_aisec` cited **CWE-494** and the bundled CWE catalogue had no
  entry for it, so every finding from that rule rendered with no description
  and no mitigations behind it. Found by the structural test added with the CI
  rules — every CWE a scanner cites must be one the catalogue can describe —
  which is also why CWE-532 and CWE-250 were added rather than approximated
  with a CWE that was already there.
- The coverage ledger asked the run manifest for a stage called `ai/ml`, while
  the stage is called `AI/ML systems`. The lookup silently missed, so a
  **crashed** AI/ML scan was reported as one that had never been configured —
  "no AI/ML scan was run" instead of "the stage failed". Both are non-clean,
  but only one of them is true, and a wrong reason in the one table people
  read is its own kind of dishonesty. The names now live in `STAGE_NAMES` with
  a test holding them to the real stage table, which is what would have caught
  it.

### Changed
- In-file suppression comments (`# nosec`, `# coldlight:ignore`) are honoured
  by `scan code` and deliberately ignored by `scan ioc`. A developer may
  reasonably silence a rule about code they wrote; a file being searched for an
  intrusion marker is, by hypothesis, a file someone else may have written, and
  letting its contents switch off its own detection would hand the suppression
  mechanism to whoever planted the marker.
- A `scan ioc` path that does not exist is refused rather than walked. An
  absent tree yields zero files and zero findings, which is indistinguishable
  from a clean result — and SECURITY.md calls a clean result that is not clean
  a vulnerability in this tool.
- `files_scanned` in an IOC report now means the file-content surface and only
  that one. One number could not be true of a content read, a walk of every
  path and a read of the config files, so each surface counts its own unit in
  `surfaces`.
- What matched is shown verbatim and the rest of the line masked, in that
  order: `port 18788 in: listen_address = "***REDACTED***"`. `redact()` hides
  quoted values, which is exactly the shape of a quoted path, a quoted port
  mapping and a quoted image reference, so masking the whole line left a line
  number and a row of asterisks where the evidence should be. Same bug class
  as the quoted path fixed in slice one, now solved structurally for every
  surface.
- The example pack must demonstrate every indicator kind, not merely a legal
  subset of them. A kind added without a worked example is a kind nobody has
  an illustration of, and someone will copy the file.
- The findings-at-a-glance table in both the HTML and Markdown reports gained
  a **Third party** column, and the sentence under it names all three
  authorities. The column is present even when it is all zeros: "no severity
  here came from outside this tool" is worth stating, and a table whose shape
  depends on its contents is a table whose arithmetic a reader has to re-check.
- An indicator report with no pack in it is now stated as UNKNOWN in the
  deliverable's limitations. It searched for nothing, and nothing found is how
  that reads in a finding count.

### Not yet
- SHA-256 only. MD5 and SHA-1 values are refused at load rather than hashed
  alongside, which is the honest failure but does mean a pack carrying older
  digests loses those entries. Computing three hashes per file to accept them
  is a cost every scan would pay for intel that is already weak.
- The importer carries no `container_image` entries, because STIX has no
  object type for an image reference. A bundle that names one in a `software`
  object is refused with that reason rather than guessed at.
- No digest of a container image layer. The image surface matches the
  reference a manifest deploys; verifying that the layer behind it is the one
  the pack names would mean reading a registry, and nothing here touches the
  network.
- Two indicators describing the *same* underlying marker will corroborate each
  other: the rule cannot tell one signal seen twice from two independent ones.
  The example pack warns a pack author off shipping such a pair, which is a
  note rather than a fix.
- The port and manifest surfaces open a fixed list of file types. A port
  declared in application source, or an image reference in a format not on
  that list, is not seen — stated in the report's surface table rather than
  left for the reader to discover.
- The indicator stage does not participate in baselines. `--baseline`
  suppresses findings accepted in a previous run for every other stage and is
  ignored here, which the stage summary states rather than leaves to be
  discovered. Whether an indicator match should ever be baselineable is the
  open question, not the plumbing.
- Nothing fetches or verifies a pack. A pack is a local file the operator
  supplies; checking one against its upstream `MANIFEST.sha256` would make
  "this is the pack the author published" something the report could claim,
  and it cannot claim it today.
- An uncovered surface does not downgrade the ledger entry to PARTIAL. Which
  surfaces a pack covers is the pack author's scope choice, not decay of the
  intel, and PARTIAL is reserved for the latter; the scan's own report carries
  the surface table.
- Network, identity and cloud telemetry carry most of any real indicator pack
  and remain out of scope, as the ledger's external classes already state.

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
