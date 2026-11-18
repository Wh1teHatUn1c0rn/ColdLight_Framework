# Security policy

## Reporting a vulnerability

Please report security issues through
[private vulnerability reporting](https://github.com/Wh1teHatUn1c0rn/ColdLight_Framework/security/advisories/new)
rather than a public issue, and give us a chance to fix it before it is
discussed in the open.

Include the ColdLight version (`coldlight doctor` prints it), what you ran, and
what happened. A proof of concept helps; a working exploit against a third
party does not and will not be accepted.

Expect an acknowledgement within a week. There is no bounty programme.

## What this tool is, and is not

This matters for triage, so it is stated here rather than buried in the README.

ColdLight **identifies and reports**. It does not weaponise. There is no
payload execution, no command-and-control, no credential capture, no
persistence, no privilege escalation, no lateral movement, no AV or EDR
evasion, and no bundled exploit code. It will not fetch, generate or run an
exploit, and the awareness-test payload it builds does exactly one thing when
run: it tells the person they are part of an authorised test.

Two consequences:

- **A feature request to add any of the above will be declined.** This is a
  scope boundary, not a backlog item, and "it would help defenders" does not
  change it.
- **A report that ColdLight "fails" to exploit something is not a
  vulnerability.** Neither is the deliberate refusal to probe an out-of-scope
  target, nor `scan history` refusing a shallow clone.

## What we do consider a vulnerability

- **A discovered secret appearing unredacted** in any report, artifact, log or
  terminal output. Everything matched by a `redact` rule must be reduced to
  `***REDACTED***` for display and to a SHA-256 fingerprint for grouping.
- **Anything that weakens TLS verification.** `coldlight_trust` is the single
  trust store, verification is always on, and there is deliberately no option
  to turn it off. A code path that bypasses it is a vulnerability even if
  nothing visibly breaks — see the structural guard in `tests/test_trust.py`.
- **A scope-gate bypass.** `coldlight scope` is deny-by-default. A target that
  is accepted without being in scope, an expired authorisation that still
  passes, or a wildcard that matches more than it should, are all in scope for
  a report.
- **A clean result that is not clean.** ColdLight's central claim is that it
  distinguishes *checked and clean* from *nobody looked*. A code path that
  reports a check as passed when it did not run, or omits a failure from the
  assurance ledger, is a security bug in this tool even though no memory is
  corrupted. Treat it as one.
- Path traversal, command injection or unsafe deserialisation reachable from
  a scanned file, a parsed SBOM, an API response or a probed endpoint. Input
  from a target is untrusted, including input from a target the operator owns.
- Anything in the collector (`coldlight serve`) reachable without the shared
  token.

## Supported versions

The latest release on `main` is the supported one. Fixes go there; there are
no backport branches.

## Operating ColdLight safely

- **Reports contain findings and may contain PII.** Awareness-test results
  carry hostnames and usernames. `.gitignore` excludes `hits.db`, `*.jsonl`
  and generated reports for that reason — keep it that way, and apply your own
  retention policy (`coldlight purge`).
- **Keep signing material out of the repository.** `*.pfx`, `*.p12`, `*.pem`
  and `*.key` are ignored. An attestation signing key belongs in a secrets
  manager or on a token, not beside the code.
- **`coldlight probe` reaches a live endpoint.** It runs only against a
  declared, in-date, signed-off scope file, and refuses otherwise. Do not
  work around that; it is the record that the test was authorised.
- **Do not run an awareness test without written authorisation.** The tool
  requires an `authorization_reference` for a production build because the
  reference is what makes the test defensible afterwards.
