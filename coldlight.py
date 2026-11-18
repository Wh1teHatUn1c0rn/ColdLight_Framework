#!/usr/bin/env python3
"""
ColdLight awareness-test framework CLI.

Turns the manual "edit source -> run PyInstaller -> stage USB" cycle into one
config-driven command.

    python coldlight.py new <name>              # scaffold campaigns/<name>/campaign.toml
    python coldlight.py validate campaign.toml  # check a config without building
    python coldlight.py build campaign.toml     # validate -> compile exe -> stage USB

Vulnerability assessment (read-only -- identify and report, never exploit):

    python coldlight.py scan deps .             # dependencies vs OSV.dev + CISA KEV
    python coldlight.py scan sbom bom.json      # a CycloneDX/SPDX SBOM (no source needed)
    python coldlight.py scan code .             # insecure patterns + leaked secrets
    python coldlight.py cve CVE-2021-44228      # one CVE from NVD, KEV cross-referenced
    python coldlight.py vulns "apache struts"   # keyword-search NVD
    python coldlight.py kev --search fortinet   # known-exploited catalog

Purple team (did anyone NOTICE the test?):

    python coldlight.py detect map              # what this exercises, per ATT&CK
    python coldlight.py detect rules --out sigma/   # Sigma rules for your SIEM
    python coldlight.py detect validate --db hits.db  # per-hit validation worksheet

One command for the whole engagement:

    python coldlight.py doctor                  # will any of this work here?
    python coldlight.py assess --init assessment.toml   # scaffold a profile
    python coldlight.py assess --profile assessment.toml
    python coldlight.py assurance assessment/   # what nobody looked at
    python coldlight.py attest create assessment/ --sign-with gpg
    python coldlight.py attest verify assessment/

The deliverable (everything above, as one report):

    python coldlight.py engagement --vuln vuln.json --code code.json \
        --mail mail.json --hits hits.db --vex triage.json --out report.html

Email authentication (why a phishing simulation succeeds):

    python coldlight.py mail audit example.com   # SPF/DKIM/DMARC/MTA-STS posture

VEX (tell downstream which findings actually apply):

    python coldlight.py vex init bom.json --out triage.json   # all under_investigation
    python coldlight.py vex emit triage.json --format openvex  # after you triage

Scope: this builds a BENIGN awareness-test payload only. It does not, and will
not, add payload execution, evasion, credential capture, persistence or C2.
The assessment commands report vulnerabilities and how to fix them; they do
not fetch, generate or run exploit code.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from coldlight_config import (
    BAKED_CONFIG_NAME,
    EXTERNAL_CONFIG_NAME,
    CampaignConfig,
    __version__,
    load_config,
    validate,
)

HERE = Path(__file__).resolve().parent
PAYLOAD_SRC = HERE / "coldlight_awareness.py"
CONFIG_SRC = HERE / "coldlight_config.py"
TRAINING_SRC = HERE / "awareness_message.html"
EXE_BASENAME = "coldlight_awareness"

# autorun.inf is INFORMATIONAL ONLY. Windows 7+ ignores AutoRun on USB/removable
# drives, so this does NOT auto-execute. The test relies on the person choosing
# to double-click the payload -- that's the point.
AUTORUN = """[Autorun]
label=Company Files
action=Open files
"""

DECOY_NOTE = (
    "This USB is part of an AUTHORIZED security-awareness test.\n"
    "There is no malware here. A real attacker would hide a malicious\n"
    "program in a file like this. Please hand found USB drives to IT/Security.\n"
)

CAMPAIGN_TEMPLATE = (HERE / "campaign.toml")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _print_validation(cfg: CampaignConfig) -> list[str]:
    errors, warnings = validate(cfg)
    for w in warnings:
        print(f"  warning: {w}")
    for e in errors:
        print(f"  ERROR:   {e}")
    if not errors and not warnings:
        print("  config looks good.")
    return errors


def _render_training_page(cfg: CampaignConfig, dest: Path) -> None:
    if not TRAINING_SRC.is_file():
        print(f"  warning: training page template not found at "
              f"{TRAINING_SRC.name}; the USB will be staged WITHOUT it.")
        print("           Run `build` from a checkout so the template is "
              "available.")
        return
    html = TRAINING_SRC.read_text(encoding="utf-8")
    html = (
        html.replace("{{SPONSOR}}", cfg.sponsor)
        .replace("{{AUTH_REFERENCE}}", cfg.authorization_reference)
        .replace("{{ENGAGEMENT_ID}}", cfg.engagement_id)
    )
    dest.write_text(html, encoding="utf-8")


def _stage_usb(cfg: CampaignConfig, exe_path: Path, out_dir: Path,
               stage_config: bool) -> Path:
    stage_dir = out_dir / "USB_stage"
    if stage_dir.exists():
        shutil.rmtree(stage_dir)
    stage_dir.mkdir(parents=True)

    shutil.copy2(exe_path, stage_dir / cfg.lure_filename)
    (stage_dir / "autorun.inf").write_text(AUTORUN, encoding="utf-8")
    _render_training_page(cfg, stage_dir / "awareness_message.html")
    (stage_dir / "README_FOUND_THIS_USB.txt").write_text(DECOY_NOTE, encoding="utf-8")

    if stage_config:
        import json
        (stage_dir / EXTERNAL_CONFIG_NAME).write_text(
            json.dumps(cfg.to_dict(), indent=2), encoding="utf-8"
        )

    return stage_dir


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_new(args: argparse.Namespace) -> int:
    dest_dir = HERE / "campaigns" / args.name
    if dest_dir.exists():
        print(f"error: {dest_dir} already exists.")
        return 1
    if not CAMPAIGN_TEMPLATE.is_file():
        # Writing an empty config and claiming success would be worse than
        # refusing. This happens when running from an installed wheel, which
        # does not ship the campaign templates -- see README ("Installing").
        print(f"error: campaign template not found at {CAMPAIGN_TEMPLATE}.")
        print("  `new` and `build` need the templates that ship beside the "
              "modules in a checkout.")
        print("  Run them from a clone of the repository rather than an "
              "installed package.")
        return 2

    dest_dir.mkdir(parents=True)
    template = CAMPAIGN_TEMPLATE.read_text(encoding="utf-8")
    (dest_dir / "campaign.toml").write_text(template, encoding="utf-8")
    print(f"Created {dest_dir / 'campaign.toml'}")
    print("Edit it, then: python coldlight.py build " + str(dest_dir / "campaign.toml"))
    return 0


def _require_config(path: str | Path) -> Path | None:
    """Resolve a required campaign config, or explain why we can't."""
    config_path = Path(path)
    if config_path.is_file():
        return config_path

    print(f"error: no campaign config at {config_path}")
    print("  Pass one explicitly, or scaffold a new campaign first:")
    print("    coldlight new <name>        # writes campaigns/<name>/campaign.toml")
    print("    coldlight validate campaigns/<name>/campaign.toml")
    return None


def cmd_validate(args: argparse.Namespace) -> int:
    config_path = _require_config(args.config)
    if config_path is None:
        return 2
    cfg = load_config(config_path)
    print(f"Validating {args.config}:")
    errors = _print_validation(cfg)
    return 1 if errors else 0


def cmd_build(args: argparse.Namespace) -> int:
    config_path = _require_config(args.config)
    if config_path is None:
        return 2
    cfg = load_config(config_path)

    print(f"Campaign config: {config_path}")
    errors = _print_validation(cfg)
    if errors and not args.allow_placeholders:
        print("\nBuild aborted: fix the errors above, or pass --allow-placeholders "
              "for a lab/testing build.")
        return 1
    if errors:
        print("\nProceeding with placeholders (--allow-placeholders). "
              "NOT for production deployment.\n")

    import importlib.util
    if importlib.util.find_spec("PyInstaller") is None:
        # Clearer than letting the subprocess fail with a module-not-found.
        print('\nPyInstaller is not installed. Run: pip install "coldlight[build]"')
        return 1

    out_dir = Path(args.output).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="coldlight_build_") as tmp:
        tmp_path = Path(tmp)
        baked = tmp_path / BAKED_CONFIG_NAME
        import json
        baked.write_text(json.dumps(cfg.to_dict()), encoding="utf-8")

        add_data = f"{baked}{__import__('os').pathsep}."
        pyi_cmd = [
            sys.executable, "-m", "PyInstaller",
            "--onefile",
            "--console" if args.console else "--noconsole",
            "--name", EXE_BASENAME,
            "--clean", "--noconfirm",
            "--distpath", str(out_dir / "dist"),
            "--workpath", str(tmp_path / "work"),
            "--specpath", str(tmp_path),
            "--add-data", add_data,
            "--paths", str(HERE),            # so coldlight_config is importable
        ]
        if args.icon and Path(args.icon).is_file():
            pyi_cmd += ["--icon", str(Path(args.icon).resolve())]
        pyi_cmd.append(str(PAYLOAD_SRC))

        print("\nCompiling payload with PyInstaller ...")
        result = subprocess.run(pyi_cmd, cwd=str(HERE))
        if result.returncode != 0:
            print("Build failed: PyInstaller returned a non-zero exit code.")
            return result.returncode

    exe_path = out_dir / "dist" / f"{EXE_BASENAME}.exe"
    if not exe_path.is_file():
        print(f"Build failed: expected exe not found at {exe_path}")
        return 1

    stage_dir = _stage_usb(cfg, exe_path, out_dir, args.stage_config)

    print("\nBuild complete.")
    print(f"  exe   : {exe_path}")
    print(f"  USB   : {stage_dir}  (copy the CONTENTS onto each stick)")
    print(f"  lure  : {cfg.lure_filename}")
    print(f"  config baked in: engagement={cfg.engagement_id!r}, "
          f"collector={'set' if cfg.collector_url else 'local-only'}")
    if args.stage_config:
        print(f"  {EXTERNAL_CONFIG_NAME} staged on USB (editable override; "
              f"breaks the lure's cover -- remove for real drops).")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    import coldlight_report as rr

    conn = rr.connect(args.db)
    for logpath in (args.ingest or []):
        p = Path(logpath)
        if not p.is_file():
            print(f"  skip (not found): {logpath}")
            continue
        new, seen = rr.ingest_jsonl(conn, p)
        print(f"  ingested {logpath}: {new} new of {seen} records")

    stats = rr.compute_stats(conn)
    print()
    print(rr.text_summary(stats))

    if args.csv:
        n = rr.export_csv(conn, args.csv)
        print(f"\nExported {n} rows to {args.csv}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import coldlight_collector
    import coldlight_safelist

    patterns = coldlight_safelist.load_patterns(args.safelist) if args.safelist else []
    coldlight_collector.serve(args.host, args.port, args.token, args.db,
                           safelist=patterns, retention_days=args.retention_days)
    return 0


def cmd_purge(args: argparse.Namespace) -> int:
    import coldlight_report as rr

    if not (args.older_than or args.before or args.engagement):
        print("purge requires at least one of --older-than, --before, --engagement")
        return 1
    conn = rr.connect(args.db)
    n = rr.purge(conn, older_than_days=args.older_than, before=args.before,
                 engagement=args.engagement, dry_run=not args.yes)
    if args.yes:
        print(f"Purged {n} row(s) from {args.db}.")
    else:
        print(f"[dry-run] {n} row(s) match. Re-run with --yes to actually delete.")
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    import os

    import coldlight_sign

    password = os.environ.get(args.password_env) if args.password_env else None
    return coldlight_sign.sign(
        args.exe, pfx=args.pfx, password=password, thumbprint=args.thumbprint,
        timestamp_url=args.timestamp_url, verify=not args.no_verify,
        dry_run=args.dry_run, signtool=args.signtool,
    )


def cmd_qr(args: argparse.Namespace) -> int:
    try:
        import qrcode  # noqa: F401
    except ImportError:
        print('qrcode is not installed. Run: pip install "coldlight[qr]"')
        return 1
    import coldlight_qr

    url, out = coldlight_qr.write_qr_svg(args.base_url, args.campaign, args.tag,
                                      out=args.out, caption=args.caption, scale=args.scale)
    print(f"URL : {url}")
    print(f"SVG : {out}")
    return 0


def _apply_baseline(source: str, findings, args, *, root=None, domain=""):
    """Handle --baseline / --update-baseline for a scan command.

    Returns None when no baseline is in play (the caller keeps its normal
    --fail-on behaviour), otherwise the exit code to use. With a baseline,
    --fail-on applies to NEW findings only -- that is the whole point.
    """
    import coldlight_baseline as bl

    path = getattr(args, "baseline", None)
    update = getattr(args, "update_baseline", False)
    if not path and not update:
        return None
    path = path or bl.DEFAULT_BASELINE_PATH

    try:
        existing = bl.load_baseline(path)
    except bl.BaselineError as exc:
        print(f"error: {exc}")
        return 2

    if update:
        merged = bl.merge_baseline(existing, source, findings,
                                   root=root, domain=domain)
        bl.save_baseline(merged, path)
        owned = sum(1 for entry in merged.entries.values()
                    if entry.source == source)
        print(f"\nBaseline updated: {path}")
        print(f"  {owned} {source} entry/entries accepted; "
              f"{len(merged.entries)} total in the file")
        print("  Commit it so the whole team shares the same accepted state.")
        return 0

    diff = bl.diff_findings(source, findings, existing, root=root, domain=domain)
    print()
    print(bl.diff_report(diff, root=root, domain=domain))

    if args.fail_on:
        try:
            if diff.new_meets(args.fail_on):
                floor = bl.SEVERITY_ORDER[args.fail_on.upper()]
                count = sum(
                    1 for f in diff.new
                    if bl.SEVERITY_ORDER.get(bl.severity_of(f), 0) >= floor
                )
                print(f"\nFAIL: {count} new finding(s) at or above "
                      f"{args.fail_on.upper()}.")
                print("  accept them with --update-baseline")
                return 1
        except ValueError as exc:
            print(f"error: {exc}")
            return 2
    return 0


def _add_baseline_args(parser) -> None:
    parser.add_argument("--baseline", default=None, metavar="PATH",
                        help="compare against this baseline and report only "
                             "findings new since it was accepted")
    parser.add_argument("--update-baseline", action="store_true",
                        help="accept the current findings as the baseline "
                             f"(default path: .coldlight/baseline.json)")


def _apply_exploit_intel(findings, args) -> list[str]:
    """Attach EPSS and Exploit-DB metadata. Returns any non-fatal notes.

    On by default because it is prioritisation data, and a CVSS 9.8 nobody is
    exploiting matters less than a 7.5 with a verified public exploit. Never
    fatal: enrichment failing must not lose a scan's findings.
    """
    if getattr(args, "no_exploit_intel", False) or not findings:
        return []

    import coldlight_exploitintel as ei
    import coldlight_vulnintel as vi

    notes: list[str] = []
    cves = [f.identifier for f in findings] + [
        alias for f in findings for alias in f.aliases
    ]

    try:
        scored = ei.apply_epss(findings, ei.fetch_epss(cves))
        if scored:
            notes.append(f"EPSS attached to {scored} finding(s)")
    except vi.VulnIntelError as exc:
        notes.append(f"EPSS unavailable: {exc}")

    try:
        index = ei.load_exploitdb_index()
        matched = ei.apply_exploitdb(findings, index)
        if matched:
            notes.append(f"public exploits found for {matched} finding(s)")
    except vi.VulnIntelError as exc:
        notes.append(f"Exploit-DB index unavailable: {exc}")

    return notes


def _add_exploit_intel_args(parser) -> None:
    parser.add_argument("--no-exploit-intel", action="store_true",
                        help="skip EPSS and Exploit-DB enrichment (offline, "
                             "or to avoid the one-off index download)")


def _write_json(path: str, payload: dict) -> None:
    import json
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"\nJSON written to {path}")


def cmd_cve(args: argparse.Namespace) -> int:
    """Look one CVE up in NVD and cross-reference the CISA KEV catalog."""
    import coldlight_vulnintel as vi

    try:
        finding = vi.nvd_lookup(args.cve_id)
    except ValueError as exc:
        print(f"error: {exc}")
        return 2
    except vi.VulnIntelError as exc:
        print(f"error: {exc}")
        return 3

    if finding is None:
        print(f"{args.cve_id.upper()}: not found in NVD.")
        return 1

    try:
        vi.apply_kev([finding], vi.kev_index())
    except vi.VulnIntelError as exc:
        print(f"  (KEV cross-reference unavailable: {exc})\n")

    for note in _apply_exploit_intel([finding], args):
        print(f"  {note}")

    print(vi.format_finding(finding, verbose=True))
    if args.json:
        _write_json(args.json, finding.to_dict())
    return 0


def cmd_vulns(args: argparse.Namespace) -> int:
    """Keyword-search NVD for known vulnerabilities in a product."""
    import coldlight_vulnintel as vi

    try:
        findings = vi.nvd_search(args.keywords, limit=args.limit, exact=args.exact)
    except vi.VulnIntelError as exc:
        print(f"error: {exc}")
        return 3

    if not findings:
        print(f"No NVD records matched {args.keywords!r}.")
        return 1

    try:
        vi.apply_kev(findings, vi.kev_index())
    except vi.VulnIntelError:
        pass

    if args.kev_only:
        findings = [f for f in findings if f.kev]
        if not findings:
            print(f"No KEV-listed CVEs among the matches for {args.keywords!r}.")
            return 1

    _apply_exploit_intel(findings, args)
    findings = vi.sort_findings(findings)
    print(f"{len(findings)} record(s) for {args.keywords!r} "
          f"(source: NVD; KEV cross-referenced)\n")
    for finding in findings:
        print(vi.format_finding(finding, verbose=args.verbose))
        print()

    if args.json:
        _write_json(args.json, {"query": args.keywords,
                                "findings": [f.to_dict() for f in findings]})
    return 0


def cmd_kev(args: argparse.Namespace) -> int:
    """Query the CISA Known Exploited Vulnerabilities catalog."""
    import coldlight_vulnintel as vi

    try:
        data = vi.load_kev(refresh=args.refresh)
    except vi.VulnIntelError as exc:
        print(f"error: {exc}")
        return 3

    entries = data.get("vulnerabilities", []) or []
    print(f"CISA KEV catalog: {len(entries)} entries "
          f"(released {data.get('dateReleased', 'unknown')[:10]})")

    if args.search:
        needle = args.search.lower()
        hits = [
            e for e in entries
            if needle in (e.get("vendorProject", "") + " " + e.get("product", "")
                          + " " + e.get("cveID", "")
                          + " " + e.get("vulnerabilityName", "")).lower()
        ]
        print(f"{len(hits)} match {args.search!r}\n")
        for entry in hits[: args.limit]:
            ransom = ("  [ransomware]"
                      if (entry.get("knownRansomwareCampaignUse", "").lower() == "known")
                      else "")
            print(f"{entry.get('cveID', '')}  {entry.get('vendorProject', '')} "
                  f"{entry.get('product', '')}{ransom}")
            print(f"    {entry.get('vulnerabilityName', '')}")
            print(f"    added {entry.get('dateAdded', '')}  |  "
                  f"due {entry.get('dueDate', '')}")
            print(f"    action: {entry.get('requiredAction', '')}")
            print()
    return 0


def cmd_scan_deps(args: argparse.Namespace) -> int:
    """Check dependency manifests against OSV + KEV."""
    import coldlight_vulnintel as vi

    def progress(done: int, total: int) -> None:
        if not args.quiet:
            print(f"\r  checking packages: {done}/{total}", end="", flush=True)

    print(f"Scanning {args.path} for dependency manifests ...")
    result = vi.scan_dependencies(args.path, workers=args.workers, progress=progress)
    if not args.quiet:
        print()

    if args.enrich and result.findings:
        print("Enriching from NVD (rate-limited; set NVD_API_KEY to speed up) ...")
        n = vi.enrich_with_nvd(result.findings)
        print(f"  enriched {n} finding(s)")

    try:
        vi.apply_kev(result.findings, vi.kev_index())
    except vi.VulnIntelError as exc:
        result.errors.append(f"KEV cross-reference unavailable: {exc}")

    for note in _apply_exploit_intel(result.findings, args):
        print(f"  {note}")
    result.findings = vi.sort_findings(result.findings)

    print()
    print(vi.text_report(result, verbose=args.verbose))

    if args.json:
        _write_json(args.json, vi.json_report(result))

    gated = _apply_baseline("dep", result.findings, args)
    if gated is not None:
        return gated

    if args.fail_on:
        try:
            if vi.meets_threshold(result.findings, args.fail_on):
                print(f"\nFAIL: findings at or above {args.fail_on.upper()}.")
                return 1
        except ValueError as exc:
            print(f"error: {exc}")
            return 2
    return 0


def cmd_scan_sbom(args: argparse.Namespace) -> int:
    """Check the components listed in a CycloneDX/SPDX SBOM against OSV."""
    import coldlight_sbom
    import coldlight_vulnintel as vi

    def progress(done: int, total: int) -> None:
        if not args.quiet:
            print(f"\r  checking components: {done}/{total}", end="", flush=True)

    print(f"Reading SBOM {args.sbom} ...")

    if args.inventory_only:
        # Summarise only -- don't touch the network.
        try:
            sbom = coldlight_sbom.load_sbom(args.sbom)
        except coldlight_sbom.SbomError as exc:
            print(f"error: {exc}")
            return 2
        print()
        print(coldlight_sbom.inventory_report(sbom))
        return 0

    try:
        result, sbom = vi.scan_sbom(args.sbom, workers=args.workers,
                                    progress=progress)
    except coldlight_sbom.SbomError as exc:
        print(f"error: {exc}")
        return 2
    if not args.quiet:
        print()

    print()
    # The scan report below repeats the NOT CHECKED warning, so don't duplicate it.
    print(coldlight_sbom.inventory_report(sbom, show_skips=False))

    if not result.packages_checked:
        print("\nNothing checkable in this SBOM -- see the reasons above.")
        return 1

    if args.enrich and result.findings:
        print("\nEnriching from NVD (rate-limited; set NVD_API_KEY to speed "
              "up) ...")
        n = vi.enrich_with_nvd(result.findings)
        print(f"  enriched {n} finding(s)")

    try:
        vi.apply_kev(result.findings, vi.kev_index())
    except vi.VulnIntelError as exc:
        result.errors.append(f"KEV cross-reference unavailable: {exc}")

    for note in _apply_exploit_intel(result.findings, args):
        print(f"  {note}")
    result.findings = vi.sort_findings(result.findings)

    print()
    print(vi.text_report(result, verbose=args.verbose))

    if args.json:
        _write_json(args.json, vi.json_report(result))

    gated = _apply_baseline("dep", result.findings, args)
    if gated is not None:
        return gated

    if args.fail_on:
        try:
            if vi.meets_threshold(result.findings, args.fail_on):
                print(f"\nFAIL: findings at or above {args.fail_on.upper()}.")
                return 1
        except ValueError as exc:
            print(f"error: {exc}")
            return 2
    return 0


def cmd_scan_history(args: argparse.Namespace) -> int:
    """Scan git history for committed secrets. Read-only."""
    import coldlight_history as hist

    print(f"Scanning the git history of {args.path} for committed "
          f"secrets ...")
    if args.exclude:
        print(f"  excluding: {', '.join(args.exclude)}")

    try:
        result = hist.scan_history(
            args.path, max_commits=args.max_commits,
            since=args.since or "", exclude=args.exclude,
            allow_shallow=args.allow_shallow)
    except hist.HistoryError as exc:
        print(f"error: {exc}")
        return 2

    print()
    print(hist.text_report(result, removed_only=args.removed_only))

    if args.json:
        _write_json(args.json, hist.json_report(result))

    if not result.assessed:
        # A shallow or truncated history must never exit 0: that would make
        # "we could not look" indistinguishable from "there is nothing here".
        return 2

    findings = (result.recoverable_only if args.removed_only
                else result.findings)

    gated = _apply_baseline("history", findings, args, root=args.path)
    if gated is not None:
        return gated

    if args.fail_on:
        try:
            if hist.meets_threshold(findings, args.fail_on):
                print()
                print(f"FAIL: findings at or above {args.fail_on.upper()}.")
                return 1
        except ValueError as exc:
            print(f"error: {exc}")
            return 2
    return 0


def cmd_scan_ai(args: argparse.Namespace) -> int:
    """Assess AI/ML code and model artifacts. Static, read-only."""
    import coldlight_aisec as ai

    print(f"Scanning {args.path} for AI/ML security issues ...")
    if args.exclude:
        print(f"  excluding: {', '.join(args.exclude)}")
    result = ai.scan_ai(args.path, exclude=args.exclude)
    print()
    print(ai.text_report(result, show_remediation=not args.no_fix_hints))

    if args.json:
        _write_json(args.json, ai.json_report(result))

    gated = _apply_baseline("ai", result.findings, args, root=args.path)
    if gated is not None:
        return gated

    if args.fail_on:
        try:
            if ai.meets_threshold(result.findings, args.fail_on):
                print()
                print(f"FAIL: findings at or above {args.fail_on.upper()}.")
                return 1
        except ValueError as exc:
            print(f"error: {exc}")
            return 2
    return 0


def cmd_scan_code(args: argparse.Namespace) -> int:
    """Static analysis for insecure patterns and leaked secrets."""
    import coldlight_codescan as cs

    print(f"Scanning {args.path} ...")
    if args.exclude:
        print(f"  excluding: {', '.join(args.exclude)}")
    result = cs.scan_code(args.path, exclude=args.exclude)
    print()
    print(cs.text_report(result, show_remediation=not args.no_fix_hints))

    if args.json:
        _write_json(args.json, cs.json_report(result))

    gated = _apply_baseline("code", result.findings, args, root=args.path)
    if gated is not None:
        return gated

    if args.fail_on:
        try:
            if cs.meets_threshold(result.findings, args.fail_on):
                print(f"\nFAIL: findings at or above {args.fail_on.upper()}.")
                return 1
        except ValueError as exc:
            print(f"error: {exc}")
            return 2
    return 0


def _maybe_config(path: str | None):
    """Load a campaign config if one was supplied and exists."""
    if not path:
        return None
    candidate = Path(path)
    if not candidate.is_file():
        print(f"  (config not found, emitting generic output only: {path})")
        return None
    return load_config(candidate)


def cmd_detect_map(args: argparse.Namespace) -> int:
    import coldlight_detect as rd

    print(rd.mapping_report())
    return 0


def cmd_detect_rules(args: argparse.Namespace) -> int:
    import coldlight_detect as rd

    cfg = _maybe_config(args.config)
    rules = rd.generate_rules(cfg)

    if args.stdout:
        for rule in rules:
            print(f"# --- {rule.filename} ---")
            print(rule.to_yaml())
        return 0

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    for rule in rules:
        (out_dir / rule.filename).write_text(rule.to_yaml(), encoding="utf-8")
        print(f"  {rule.level:<13} {rule.filename}")

    print(f"\n{len(rules)} Sigma rule(s) written to {out_dir}")
    if cfg is None:
        print("Pass --config campaign.toml to also emit campaign-pinned rules "
              "(exact lure filename + collector host).")
    print("Convert for your SIEM with: sigma convert -t <backend> "
          f"{out_dir}")
    return 0


def cmd_detect_navigator(args: argparse.Namespace) -> int:
    import coldlight_detect as rd

    Path(args.out).write_text(rd.navigator_json(args.name), encoding="utf-8")
    print(f"ATT&CK Navigator layer written to {args.out}")
    print("Load it at https://mitre-attack.github.io/attack-navigator/ "
          "(Open Existing Layer -> Upload from local).")
    return 0


def cmd_detect_checklist(args: argparse.Namespace) -> int:
    import coldlight_detect as rd

    cfg = _maybe_config(args.config)
    text = rd.checklist_markdown(cfg)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"Checklist written to {args.out}")
    else:
        print(text)
    return 0


def cmd_detect_validate(args: argparse.Namespace) -> int:
    import coldlight_detect as rd
    import coldlight_report as rr

    if not Path(args.db).is_file():
        print(f"error: no database at {args.db}. Ingest hits first: "
              f"coldlight report --ingest <log.jsonl>")
        return 1

    conn = rr.connect(args.db)
    hits = rr.all_hits(conn)
    if not args.include_excluded:
        hits = [h for h in hits if not h.get("excluded")]
    if args.vector:
        hits = [h for h in hits
                if (h.get("vector") or "usb").lower() == args.vector.lower()]

    cfg = _maybe_config(args.config)
    text = rd.validation_worksheet(hits, cfg)

    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"Worksheet for {len(hits)} hit(s) written to {args.out}")
    else:
        print(text)
    return 0


def _findings_from_json(path: str):
    """Rebuild Finding objects from a saved `scan --json` report."""
    import json

    import coldlight_vulnintel as vi

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    allowed = set(vi.Finding("x").to_dict())
    findings = []
    for entry in data.get("findings", []) or []:
        clean = {k: v for k, v in entry.items() if k in allowed}
        if clean.get("identifier"):
            findings.append(vi.Finding(**clean))
    return findings, data.get("inventory_source", "saved report")


def cmd_vex_init(args: argparse.Namespace) -> int:
    """Create a VEX triage file from scan findings."""
    import coldlight_sbom
    import coldlight_vex as vx
    import coldlight_vulnintel as vi

    author = args.author or ""
    product_name = args.product_name or ""
    product_version = args.product_version or ""

    if args.config:
        cfg = _maybe_config(args.config)
        if cfg and not author:
            author = cfg.sponsor

    def progress(done: int, total: int) -> None:
        if not args.quiet:
            print(f"\r  checking: {done}/{total}", end="", flush=True)

    if args.from_json:
        findings, source = _findings_from_json(args.from_json)
        print(f"Loaded {len(findings)} finding(s) from {args.from_json}")
    else:
        target = Path(args.target)
        if target.is_dir():
            print(f"Scanning {target} ...")
            result = vi.scan_dependencies(target, workers=args.workers,
                                          progress=progress)
            source = "dependency manifests"
        else:
            print(f"Reading SBOM {target} ...")
            try:
                result, sbom = vi.scan_sbom(target, workers=args.workers,
                                            progress=progress)
            except coldlight_sbom.SbomError as exc:
                print(f"error: {exc}")
                return 2
            source = result.source_label
            if not product_name:
                product_name = sbom.document_name
        if not args.quiet:
            print()
        try:
            vi.apply_kev(result.findings, vi.kev_index())
        except vi.VulnIntelError as exc:
            print(f"  (KEV cross-reference unavailable: {exc})")
        findings = vi.sort_findings(result.findings)

    product = vx.Product(
        name=product_name or "CHANGE-ME-PRODUCT",
        version=product_version,
        purl=args.product_purl or "",
    )
    doc = vx.from_scan(findings, product=product, author=author,
                       source_label=source)

    vx.save_triage(doc, args.out)
    print()
    print(vx.text_summary(doc))
    print()
    print(f"Triage file written to {args.out}")
    print("Record your decisions in it, then: "
          f"python coldlight.py vex emit {args.out} --format openvex")
    return 0


def cmd_vex_validate(args: argparse.Namespace) -> int:
    import coldlight_vex as vx

    try:
        doc = vx.load_triage(args.triage)
    except vx.VexError as exc:
        print(f"error: {exc}")
        return 2

    errors, warnings = vx.validate(doc)
    print(vx.text_summary(doc))
    print()
    for warning in warnings:
        print(f"  warning: {warning}")
    for error in errors:
        print(f"  ERROR:   {error}")

    if errors:
        print(f"\n{len(errors)} error(s): this would not be conformant VEX.")
        return 1
    print("\nValid. Ready to emit.")
    return 0


def cmd_vex_emit(args: argparse.Namespace) -> int:
    import json

    import coldlight_vex as vx

    try:
        doc = vx.load_triage(args.triage)
        payload = vx.emit(doc, args.format)
    except vx.VexError as exc:
        print(f"error: {exc}")
        return 1

    _, warnings = vx.validate(doc)
    for warning in warnings:
        print(f"  warning: {warning}")

    text = json.dumps(payload, indent=2) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"\n{args.format} VEX written to {args.out}")
        print(f"  {len(doc.statements)} statement(s): "
              + ", ".join(f"{k}={v}" for k, v in doc.status_counts().items()))
    else:
        print(text)
    return 0


def cmd_mail_audit(args: argparse.Namespace) -> int:
    """Audit a domain's email authentication posture (passive DNS)."""
    import coldlight_mail as rm

    selectors = tuple(rm.COMMON_SELECTORS)
    if args.selector:
        extra = tuple(s for s in args.selector if s not in selectors)
        selectors = extra + selectors

    print(f"Auditing {args.domain} (passive: public DNS over HTTPS"
          f"{'' if args.no_fetch else ' + the well-known MTA-STS policy'}) ...")
    try:
        audit = rm.audit_domain(args.domain, fetch_policy=not args.no_fetch,
                                selectors=selectors, workers=args.workers)
    except rm.MailAuditError as exc:
        print(f"error: {exc}")
        return 2

    print()
    if args.records_only:
        records = rm.recommended_records(audit)
        if not records:
            print(f"{audit.domain}: nothing to add -- "
                  f"SPF, DMARC and reporting are all in place.")
        for line in records:
            print(line)
        return 0

    print(rm.text_report(audit, verbose=args.verbose))

    if args.json:
        _write_json(args.json, audit.to_dict())

    gated = _apply_baseline("mail", audit.findings, args, domain=audit.domain)
    if gated is not None:
        return gated

    if args.fail_on:
        try:
            if rm.meets_threshold(audit.findings, args.fail_on):
                print(f"FAIL: findings at or above {args.fail_on.upper()}.")
                return 1
        except ValueError as exc:
            print(f"error: {exc}")
            return 2
    return 0


def cmd_scope(args: argparse.Namespace) -> int:
    """Validate the authorization/scope file, or ask it about a target."""
    import coldlight_scope as rs

    if args.init:
        try:
            path = rs.write_template(args.init)
        except rs.ScopeError as exc:
            print(f"error: {exc}")
            return 2
        print(f"Wrote {path}")
        print()
        print("Fill in authorization_reference, the dates and the targets, "
              "then check it:")
        print(f"  coldlight scope {path}")
        return 0

    if not args.file:
        print("error: give a scope file, or --init PATH to create one.")
        print()
        print("Example:")
        print("  coldlight scope --init scope.toml")
        print("  coldlight scope scope.toml --target https://staging.example.com")
        return 2

    try:
        scope = rs.load_scope(args.file)
    except rs.ScopeError as exc:
        print(f"error: {exc}")
        return 2

    print(scope.summary())

    exit_code = 0
    if args.target:
        print()
        print("Target decisions:")
        for target in args.target:
            decision = scope.check(target)
            print(f"  {decision}")
            if not decision.allowed:
                exit_code = 1

    window = scope.window_error()
    if window:
        exit_code = exit_code or 1

    if args.json:
        _write_json(args.json, scope.to_dict())
    return exit_code


def cmd_probe(args: argparse.Namespace) -> int:
    """Benign injection susceptibility probing. Needs authorised scope."""
    import coldlight_canary as cn
    import coldlight_scope as rs

    try:
        scope = rs.load_scope(args.scope)
    except rs.ScopeError as exc:
        print(f"error: {exc}")
        return 2

    try:
        config = cn.probe_config(scope)
    except cn.CanaryError as exc:
        print(f"error: {exc}")
        return 2

    header_names = ", ".join(cn.redacted_headers(config["headers"])) or "(none)"
    print(f"Target        : {config['url']}")
    print(f"Authorization : {scope.authorization_reference}")
    if scope.authorized_by:
        print(f"Authorized by : {scope.authorized_by}")
    print(f"Headers       : {header_names} (values not shown)")
    print(f"Probes        : {len(cn.PROBES)} benign canaries")
    if args.dry_run:
        print("Mode          : DRY RUN -- nothing will be sent")
    print()

    try:
        run = cn.run_probes(scope, dry_run=args.dry_run)
    except rs.ScopeDenied as exc:
        print(f"REFUSED: {exc.decision.reason}")
        print(f"  target: {exc.decision.target}")
        if exc.decision.rule:
            print(f"  rule  : {exc.decision.rule}")
        print()
        print("Nothing was sent. Add the target to the scope file only if it "
              "is genuinely authorised.")
        return 2
    except cn.CanaryError as exc:
        print(f"error: {exc}")
        return 2

    print(cn.text_report(run))

    if args.json:
        _write_json(args.json, cn.json_report(run, scope))

    if args.dry_run:
        return 0

    if not run.established:
        # Nothing was established, so this is an incomplete assessment -- not
        # a clean one. Exit 2, the same as a failed stage in `assess`.
        return 2

    if args.fail_on:
        try:
            if cn.meets_threshold(cn.findings(run), args.fail_on):
                print()
                print(f"FAIL: susceptibility at or above "
                      f"{args.fail_on.upper()}.")
                return 1
        except ValueError as exc:
            print(f"error: {exc}")
            return 2
    return 0


def cmd_engagement(args: argparse.Namespace) -> int:
    """Assemble every module's findings into one deliverable."""
    import coldlight_engagement as eng

    cfg = _maybe_config(args.config) if args.config else None

    engagement = eng.Engagement(
        engagement_id=args.engagement_id or (cfg.engagement_id if cfg else ""),
        authorization_reference=(
            args.authorization
            or (cfg.authorization_reference if cfg else "")
        ),
        client=args.client or "",
        assessor=args.assessor or (cfg.sponsor if cfg else ""),
        title=args.title or "",
        period=args.period or "",
        scope=list(args.scope or []),
    )

    try:
        report = eng.build_report(
            engagement=engagement,
            vuln_paths=args.vuln or (),
            code_paths=args.code or (),
            mail_paths=args.mail or (),
            ai_paths=args.ai or (),
            probe_paths=args.probe or (),
            history_paths=args.history or (),
            hits_db=args.hits,
            vex_path=args.vex,
            group=not args.no_group,
        )
    except eng.EngagementError as exc:
        print(f"error: {exc}")
        return 2

    if not report.sources:
        print("error: no inputs given. Supply at least one of --vuln, --code, "
              "--ai, --mail or --hits.")
        print("\nExample:")
        print("  coldlight scan sbom bom.json --json vuln.json")
        print("  coldlight scan code . --json code.json --exclude 'tests/*'")
        print("  coldlight scan ai . --json ai.json")
        print("  coldlight mail audit example.com --json mail.json")
        print("  coldlight engagement --vuln vuln.json --code code.json "
              "--ai ai.json --mail mail.json --out report.html")
        return 1

    try:
        document = eng.render(report, args.format)
    except eng.EngagementError as exc:
        print(f"error: {exc}")
        return 2

    print(eng.text_summary(report))

    if args.out:
        Path(args.out).write_text(document, encoding="utf-8")
        print(f"\n{args.format} report written to {args.out}")
    else:
        print()
        print(document)
    return 0


def cmd_attest_create(args: argparse.Namespace) -> int:
    """Produce a signed, verifiable attestation for an assessment."""
    import coldlight_attest as at

    try:
        statement = at.build_statement(args.source)
        path = at.write_statement(statement, args.source)
    except at.AttestError as exc:
        print(f"error: {exc}")
        return 2

    subjects = statement["subject"]
    inputs = statement["predicate"]["inputs"]
    print(f"Attestation written to {path}")
    print(f"  {len(subjects)} subject(s), {len(inputs)} input(s) recorded "
          f"by SHA-256")

    assurance = statement["predicate"].get("assurance") or {}
    if assurance.get("present"):
        unexamined = assurance.get("unexamined") or []
        print(f"  scope attested: {assurance.get('classesExamined')} of "
              f"{assurance.get('classesInToolScope')} class(es) examined"
              + (f"; NOT assessed: {len(unexamined)}" if unexamined else ""))
    else:
        print("  warning: no assurance ledger — the breadth of this "
              "assessment is NOT attested")

    if not args.sign_with:
        print("\nUnsigned. Add --sign-with gpg|openssl|hmac to sign it.")
        return 0

    try:
        result = at.sign(path, args.sign_with, key=args.key or "",
                         key_env=args.hmac_env or "",
                         passphrase_env=args.passphrase_env or "",
                         dry_run=args.dry_run)
    except at.AttestError as exc:
        print(f"error: {exc}")
        return 2

    if args.dry_run:
        print(f"\n[dry-run] {result.detail}")
        if result.command:
            print("  " + " ".join(result.command))
        return 0

    print(f"\nSigned with {result.backend}: {result.signature_path}")
    if args.sign_with == at.BACKEND_HMAC:
        print("  NOTE: a symmetric MAC proves nothing to a third party — "
              "anyone who can verify it could also forge it.")
    return 0


def cmd_attest_verify(args: argparse.Namespace) -> int:
    import coldlight_attest as at

    try:
        result = at.verify(args.source, key=args.key or "",
                           key_env=args.hmac_env or "")
    except at.AttestError as exc:
        print(f"error: {exc}")
        return 2

    print(at.verify_report(result))
    if args.json:
        _write_json(args.json, result.to_dict())

    # result.ok is False when digests mismatch OR a signature is present and
    # INVALID. An invalid signature is evidence of tampering and must always
    # fail, regardless of flags -- it is categorically different from no
    # signature at all, where we simply cannot tell.
    if not result.ok:
        return 1
    if args.require_signature and result.signature_ok is not True:
        print("\nFAIL: --require-signature was given but no valid signature "
              "was verified.")
        return 1
    return 0


def cmd_assurance(args: argparse.Namespace) -> int:
    """Show what an assessment examined — and what nobody looked at."""
    import coldlight_assurance as asr

    try:
        ledger = asr.build_ledger(args.source)
    except asr.AssuranceError as exc:
        print(f"error: {exc}")
        return 2

    if args.format == "md":
        print(asr.markdown_ledger(ledger))
    elif args.format == "json":
        import json
        print(json.dumps(ledger.to_dict(), indent=2))
    else:
        print(asr.text_ledger(ledger))

    if args.json:
        _write_json(args.json, ledger.to_dict())

    if args.require_complete and [e for e in ledger.covered if not e.examined]:
        print("\nFAIL: not every check class in scope was examined.")
        return 1
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    """Check the external dependencies up front, rather than mid-engagement."""
    import coldlight_doctor as rd

    stages: list[str] = []
    profile_name = ""
    if args.profile:
        try:
            stages, profile_name = rd.stages_for_profile(args.profile)
        except rd.DoctorError as exc:
            print(f"error: {exc}")
            return 2
        if not stages:
            print(f"error: {args.profile} configures no stages, so there is "
                  f"nothing to check. Run `coldlight doctor` with no --profile "
                  f"to check everything.")
            return 2

    result = rd.run(offline=args.offline,
                    timeout=args.timeout or rd.DEFAULT_TIMEOUT,
                    stages=stages, profile=profile_name)
    print(rd.text_report(result))
    if args.json:
        _write_json(args.json, rd.json_report(result))
    return result.exit_code


def cmd_assess(args: argparse.Namespace) -> int:
    """Run every configured stage and produce the report."""
    import coldlight_assess as ra

    if args.init:
        try:
            path = ra.write_profile_template(args.init)
        except ra.AssessError as exc:
            print(f"error: {exc}")
            return 2
        print(f"Created {path}")
        print("Edit it, then: coldlight assess --profile " + str(path))
        return 0

    profile = ra.Profile()
    if args.profile:
        try:
            profile = ra.load_profile(args.profile)
        except ra.AssessError as exc:
            print(f"error: {exc}")
            return 2
    profile = ra.merge_args(profile, args)

    if args.config:
        cfg = _maybe_config(args.config)
        if cfg:
            profile.engagement_id = profile.engagement_id or cfg.engagement_id
            profile.authorization_reference = (
                profile.authorization_reference or cfg.authorization_reference)
            profile.assessor = profile.assessor or cfg.sponsor

    errors, warnings = ra.validate_profile(profile)
    for warning in warnings:
        print(f"  warning: {warning}")
    if errors:
        for error in errors:
            print(f"  ERROR:   {error}")
        print("\nNothing to do. Scaffold a profile with: "
              "coldlight assess --init assessment.toml")
        return 2

    stages = ", ".join(profile.configured_stages)
    print(f"Assessment: {stages}")
    print(f"Output    : {profile.out_dir}")
    print()

    # Name what will fail before spending ten minutes finding out. This does
    # not gate the run: the stage machinery already records a failure as
    # FAILED, and aborting would throw away the stages that would have worked.
    if not args.no_preflight:
        import coldlight_doctor as rd
        preflight = rd.run(stages=profile.configured_stages,
                           profile=args.profile or "")
        for line in rd.preflight_lines(preflight):
            print(line)
        print()

    # Only rewrite the line in a real terminal. Piped into a CI log, a \r
    # does not overwrite anything and every stage would appear twice.
    interactive = sys.stdout.isatty()

    def progress(index: int, total: int, name: str, stage) -> None:
        if stage is None:
            if interactive:
                print(f"[{index}/{total}] {name} ...", end="", flush=True)
            return
        prefix = "\r" if interactive else ""
        if stage.status == ra.STAGE_FAILED:
            print(f"{prefix}[{index}/{total}] {name}: FAILED — {stage.error}")
        else:
            print(f"{prefix}[{index}/{total}] {name}: {stage.summary}")

    run_result = ra.run(profile, progress=None if args.quiet else progress)

    if run_result.ledger is not None and not args.no_ledger:
        import coldlight_assurance as asr
        print()
        print(asr.text_ledger(run_result.ledger))

    print()
    print(ra.summary_report(run_result))
    return run_result.exit_code


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="ColdLight awareness-test framework CLI.")
    ap.add_argument("--version", action="version",
                    version=f"ColdLight {__version__}")
    sub = ap.add_subparsers(dest="command", required=True)

    p_new = sub.add_parser("new", help="scaffold a new campaign config")
    p_new.add_argument("name")
    p_new.set_defaults(func=cmd_new)

    p_val = sub.add_parser("validate", help="validate a campaign config")
    p_val.add_argument("config", nargs="?", default="campaign.toml")
    p_val.set_defaults(func=cmd_validate)

    p_build = sub.add_parser("build", help="validate, compile, and stage a campaign")
    p_build.add_argument("config", nargs="?", default="campaign.toml")
    p_build.add_argument("--output", default=".", help="output dir (default: cwd)")
    p_build.add_argument("--console", action="store_true",
                         help="keep a console window (useful while testing)")
    p_build.add_argument("--icon", default=None, help="path to an .ico for the exe")
    p_build.add_argument("--allow-placeholders", action="store_true",
                         help="build even if engagement/auth values are placeholders")
    p_build.add_argument("--stage-config", action="store_true",
                         help="also drop an editable campaign.json on the USB")
    p_build.set_defaults(func=cmd_build)

    p_report = sub.add_parser("report", help="summarize hits (from the DB and/or JSONL logs)")
    p_report.add_argument("--db", default="hits.db", help="SQLite path (default hits.db)")
    p_report.add_argument("--ingest", nargs="*", metavar="LOG",
                          help="JSONL hit logs to import first (e.g. collected from USBs)")
    p_report.add_argument("--csv", default=None, help="also export all hits to this CSV")
    p_report.set_defaults(func=cmd_report)

    p_serve = sub.add_parser("serve", help="run the collection server + dashboard")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.add_argument("--token", required=True, help="shared ingest/stats token")
    p_serve.add_argument("--db", default="hits.db", help="SQLite path (default hits.db)")
    p_serve.add_argument("--safelist", help="file of opt-out patterns (one per line)")
    p_serve.add_argument("--retention-days", type=int, default=None,
                         help="auto-purge hits older than N days")
    p_serve.set_defaults(func=cmd_serve)

    p_purge = sub.add_parser("purge", help="delete hits per retention policy (dry-run unless --yes)")
    p_purge.add_argument("--db", default="hits.db", help="SQLite path (default hits.db)")
    p_purge.add_argument("--older-than", type=int, metavar="DAYS",
                         help="delete hits older than DAYS")
    p_purge.add_argument("--before", metavar="ISO_DATE", help="delete hits before this date")
    p_purge.add_argument("--engagement", help="delete hits for this engagement id")
    p_purge.add_argument("--yes", action="store_true",
                         help="actually delete (omit for a dry-run count)")
    p_purge.set_defaults(func=cmd_purge)

    p_sign = sub.add_parser("sign", help="Authenticode-sign a built exe (Windows)")
    p_sign.add_argument("exe")
    p_sign.add_argument("--pfx", help="path to a .pfx/.p12 code-signing cert")
    p_sign.add_argument("--password-env", help="env var holding the PFX password")
    p_sign.add_argument("--thumbprint", help="SHA1 thumbprint of a cert in the Windows store")
    p_sign.add_argument("--timestamp-url", default="http://timestamp.digicert.com")
    p_sign.add_argument("--no-verify", action="store_true")
    p_sign.add_argument("--dry-run", action="store_true",
                        help="print the signtool command without running it")
    p_sign.add_argument("--signtool", help="explicit path to signtool.exe")
    p_sign.set_defaults(func=cmd_sign)

    p_qr = sub.add_parser("qr", help="generate a QR-code poster pointing at the landing page")
    p_qr.add_argument("--base-url", required=True, help="landing URL, e.g. https://host:8000/land")
    p_qr.add_argument("--campaign", required=True, help="engagement/campaign id (the ?c= value)")
    p_qr.add_argument("--tag", default="", help="medium/placement tag (the ?t= value)")
    p_qr.add_argument("--out", default="qr.svg", help="output SVG path")
    p_qr.add_argument("--caption", default=None, help="caption under the QR (default: campaign)")
    p_qr.add_argument("--scale", type=int, default=8, help="pixels per module")
    p_qr.set_defaults(func=cmd_qr)

    # --- vulnerability assessment (read-only: identify and report) ---------

    p_cve = sub.add_parser("cve", help="look up one CVE in NVD (+ CISA KEV flag)")
    p_cve.add_argument("cve_id", help="e.g. CVE-2021-44228")
    p_cve.add_argument("--json", default=None, help="also write the record to this file")
    _add_exploit_intel_args(p_cve)
    p_cve.set_defaults(func=cmd_cve)

    p_vulns = sub.add_parser("vulns", help="search NVD for known vulns in a product")
    p_vulns.add_argument("keywords", help='e.g. "apache struts" or "openssh 9.1"')
    p_vulns.add_argument("--limit", type=int, default=20, help="max records (default 20)")
    p_vulns.add_argument("--exact", action="store_true",
                         help="require the exact keyword phrase")
    p_vulns.add_argument("--kev-only", action="store_true",
                         help="only CVEs known to be exploited in the wild")
    p_vulns.add_argument("--verbose", "-v", action="store_true")
    p_vulns.add_argument("--json", default=None)
    _add_exploit_intel_args(p_vulns)
    p_vulns.set_defaults(func=cmd_vulns)

    p_kev = sub.add_parser("kev", help="query the CISA Known Exploited Vulns catalog")
    p_kev.add_argument("--search", default=None, help="vendor/product/CVE substring")
    p_kev.add_argument("--limit", type=int, default=25)
    p_kev.add_argument("--refresh", action="store_true", help="bypass the 24h cache")
    p_kev.set_defaults(func=cmd_kev)

    p_scan = sub.add_parser("scan", help="scan a target for vulnerabilities (read-only)")
    scan_sub = p_scan.add_subparsers(dest="scan_target", required=True)

    p_deps = scan_sub.add_parser(
        "deps", help="dependency manifests vs OSV.dev + CISA KEV")
    p_deps.add_argument("path", nargs="?", default=".", help="repo/dir to scan")
    p_deps.add_argument("--enrich", action="store_true",
                        help="fill in CVSS/CWE from NVD (slower; rate-limited)")
    p_deps.add_argument("--workers", type=int, default=8, help="parallel lookups")
    p_deps.add_argument("--fail-on", default=None,
                        metavar="SEVERITY",
                        help="exit 1 if any finding is >= this (critical/high/medium/low)")
    p_deps.add_argument("--verbose", "-v", action="store_true")
    p_deps.add_argument("--quiet", "-q", action="store_true", help="no progress counter")
    p_deps.add_argument("--json", default=None, help="write the full report here")
    _add_baseline_args(p_deps)
    _add_exploit_intel_args(p_deps)
    p_deps.set_defaults(func=cmd_scan_deps)

    p_sbom = scan_sub.add_parser(
        "sbom", help="CycloneDX/SPDX bill of materials vs OSV.dev + CISA KEV")
    p_sbom.add_argument("sbom", help="path to a CycloneDX JSON, SPDX JSON or "
                                     "SPDX tag-value file")
    p_sbom.add_argument("--inventory-only", action="store_true",
                        help="just summarise the SBOM, don't query OSV")
    p_sbom.add_argument("--enrich", action="store_true",
                        help="fill in CVSS/CWE from NVD (slower; rate-limited)")
    p_sbom.add_argument("--workers", type=int, default=8, help="parallel lookups")
    p_sbom.add_argument("--fail-on", default=None, metavar="SEVERITY",
                        help="exit 1 if any finding is >= this")
    p_sbom.add_argument("--verbose", "-v", action="store_true")
    p_sbom.add_argument("--quiet", "-q", action="store_true")
    p_sbom.add_argument("--json", default=None, help="write the full report here")
    _add_baseline_args(p_sbom)
    _add_exploit_intel_args(p_sbom)
    p_sbom.set_defaults(func=cmd_scan_sbom)

    p_ai = scan_sub.add_parser(
        "ai", help="AI/ML security: model loading, prompt injection sinks, "
                   "agency, provider secrets")
    p_ai.add_argument("path", nargs="?", default=".", help="repo/dir to scan")
    p_ai.add_argument("--exclude", action="append", default=None,
                      metavar="GLOB", help="skip paths matching this glob")
    p_ai.add_argument("--fail-on", default=None, metavar="SEVERITY",
                      help="exit 1 if any finding is >= this")
    p_ai.add_argument("--no-fix-hints", action="store_true")
    p_ai.add_argument("--json", default=None, help="write the full report here")
    _add_baseline_args(p_ai)
    p_ai.set_defaults(func=cmd_scan_ai)

    p_hist = scan_sub.add_parser(
        "history", help="secrets committed to git history, including ones "
                        "later deleted from the working tree")
    p_hist.add_argument("path", nargs="?", default=".",
                        help="git repository to scan")
    p_hist.add_argument("--exclude", action="append", default=None,
                        metavar="GLOB", help="skip paths matching this glob")
    p_hist.add_argument("--removed-only", action="store_true",
                        help="report only secrets gone from HEAD -- the ones "
                             "`scan code` cannot see")
    p_hist.add_argument("--max-commits", type=int, default=None, metavar="N",
                        help="walk at most N commits (newest first)")
    p_hist.add_argument("--since", default=None, metavar="DATE",
                        help='only commits after this date, e.g. "1 year ago"')
    p_hist.add_argument("--allow-shallow", action="store_true",
                        help="scan a shallow clone anyway; the result is "
                             "still reported as incomplete")
    p_hist.add_argument("--fail-on", default=None, metavar="SEVERITY",
                        help="exit 1 if any finding is >= this")
    p_hist.add_argument("--json", default=None,
                        help="write the full report here")
    _add_baseline_args(p_hist)
    p_hist.set_defaults(func=cmd_scan_history)

    p_code = scan_sub.add_parser(
        "code", help="static analysis for insecure patterns and leaked secrets")
    p_code.add_argument("path", nargs="?", default=".", help="repo/dir to scan")
    p_code.add_argument("--exclude", action="append", metavar="GLOB", default=None,
                        help="skip paths matching this glob (repeatable), "
                             'e.g. --exclude "tests/*"')
    p_code.add_argument("--fail-on", default=None, metavar="SEVERITY",
                        help="exit 1 if any finding is >= this")
    p_code.add_argument("--no-fix-hints", action="store_true",
                        help="omit remediation guidance from the report")
    p_code.add_argument("--json", default=None, help="write the full report here")
    _add_baseline_args(p_code)
    p_code.set_defaults(func=cmd_scan_code)

    # --- purple team: prove the blue team would have seen it ---------------

    p_detect = sub.add_parser(
        "detect", help="ATT&CK mapping, Sigma rules, and detection validation")
    detect_sub = p_detect.add_subparsers(dest="detect_action", required=True)

    p_map = detect_sub.add_parser(
        "map", help="show what ColdLight exercises, mapped to MITRE ATT&CK")
    p_map.set_defaults(func=cmd_detect_map)

    p_rules = detect_sub.add_parser("rules", help="emit Sigma detection rules")
    p_rules.add_argument("--out", default="sigma", help="output dir (default: sigma/)")
    p_rules.add_argument("--config", default=None,
                         help="campaign.toml, to also emit campaign-pinned rules")
    p_rules.add_argument("--stdout", action="store_true",
                         help="print the rules instead of writing files")
    p_rules.set_defaults(func=cmd_detect_rules)

    p_nav = detect_sub.add_parser(
        "navigator", help="emit an ATT&CK Navigator layer (JSON)")
    p_nav.add_argument("--out", default="attack_layer.json")
    p_nav.add_argument("--name", default=None, help="layer name")
    p_nav.set_defaults(func=cmd_detect_navigator)

    p_check = detect_sub.add_parser(
        "checklist", help="blue-team validation checklist (markdown)")
    p_check.add_argument("--config", default=None, help="campaign.toml")
    p_check.add_argument("--out", default=None, help="write here instead of stdout")
    p_check.set_defaults(func=cmd_detect_checklist)

    p_val = detect_sub.add_parser(
        "validate",
        help="turn recorded hits into a per-hit detection-validation worksheet")
    p_val.add_argument("--db", default="hits.db", help="SQLite path (default hits.db)")
    p_val.add_argument("--config", default=None, help="campaign.toml")
    p_val.add_argument("--vector", default=None,
                       help="only this vector (usb/link/qr)")
    p_val.add_argument("--include-excluded", action="store_true",
                       help="also include safe-listed hits")
    p_val.add_argument("--out", default=None, help="write here instead of stdout")
    p_val.set_defaults(func=cmd_detect_validate)

    # --- VEX: tell downstream which findings actually apply ---------------

    p_vex = sub.add_parser(
        "vex", help="produce VEX (OpenVEX / CycloneDX / CSAF) from findings")
    vex_sub = p_vex.add_subparsers(dest="vex_action", required=True)

    p_vinit = vex_sub.add_parser(
        "init", help="create a triage file from a scan (all under_investigation)")
    p_vinit.add_argument("target", nargs="?", default=".",
                         help="SBOM file, or a directory to scan")
    p_vinit.add_argument("--from-json", default=None,
                         help="reuse a saved `scan --json` report instead of "
                              "re-querying OSV")
    p_vinit.add_argument("--out", default="vex_triage.json")
    p_vinit.add_argument("--product-name", default=None)
    p_vinit.add_argument("--product-version", default=None)
    p_vinit.add_argument("--product-purl", default=None,
                         help="purl of the product you ship (recommended)")
    p_vinit.add_argument("--author", default=None,
                         help="who is making these assertions")
    p_vinit.add_argument("--config", default=None,
                         help="campaign.toml, to take the sponsor as author")
    p_vinit.add_argument("--workers", type=int, default=8)
    p_vinit.add_argument("--quiet", "-q", action="store_true")
    p_vinit.set_defaults(func=cmd_vex_init)

    p_vcheck = vex_sub.add_parser(
        "validate", help="check a triage file would produce conformant VEX")
    p_vcheck.add_argument("triage", nargs="?", default="vex_triage.json")
    p_vcheck.set_defaults(func=cmd_vex_validate)

    p_vemit = vex_sub.add_parser("emit", help="emit a VEX document")
    p_vemit.add_argument("triage", nargs="?", default="vex_triage.json")
    p_vemit.add_argument("--format", default="openvex",
                         choices=["openvex", "cyclonedx", "csaf"])
    p_vemit.add_argument("--out", default=None,
                         help="write here instead of stdout")
    p_vemit.set_defaults(func=cmd_vex_emit)

    # --- email authentication posture (why phishing works on you) ---------

    p_mail = sub.add_parser(
        "mail", help="email authentication posture (SPF/DKIM/DMARC/MTA-STS)")
    mail_sub = p_mail.add_subparsers(dest="mail_action", required=True)

    p_maudit = mail_sub.add_parser(
        "audit", help="can an attacker send mail as this domain?")
    p_maudit.add_argument("domain", help="e.g. example.com")
    p_maudit.add_argument("--selector", action="append", default=None,
                          metavar="NAME",
                          help="additional DKIM selector to probe (repeatable)")
    p_maudit.add_argument("--no-fetch", action="store_true",
                          help="DNS only; skip the MTA-STS policy HTTPS fetch")
    p_maudit.add_argument("--records-only", action="store_true",
                          help="print just the recommended DNS records")
    p_maudit.add_argument("--fail-on", default=None, metavar="SEVERITY",
                          help="exit 1 if any finding is >= this")
    p_maudit.add_argument("--workers", type=int, default=8)
    p_maudit.add_argument("--verbose", "-v", action="store_true")
    p_maudit.add_argument("--json", default=None, help="write the full report here")
    _add_baseline_args(p_maudit)
    p_maudit.set_defaults(func=cmd_mail_audit)

    # --- the deliverable ---------------------------------------------------

    p_eng = sub.add_parser(
        "engagement",
        help="assemble all findings into one report (HTML/Markdown/JSON)")
    p_eng.add_argument("--vuln", action="append", default=None, metavar="JSON",
                       help="a `scan deps`/`scan sbom` --json report (repeatable)")
    p_eng.add_argument("--code", action="append", default=None, metavar="JSON",
                       help="a `scan code` --json report (repeatable)")
    p_eng.add_argument("--mail", action="append", default=None, metavar="JSON",
                       help="a `mail audit` --json report (repeatable)")
    p_eng.add_argument("--ai", action="append", default=None, metavar="JSON",
                       help="a `scan ai` --json report (repeatable)")
    p_eng.add_argument("--probe", action="append", default=None,
                       metavar="JSON",
                       help="a `probe` --json report (repeatable)")
    p_eng.add_argument("--history", action="append", default=None,
                       metavar="JSON",
                       help="a `scan history` --json report (repeatable)")
    p_eng.add_argument("--hits", default=None, metavar="DB",
                       help="awareness hits database (hits.db)")
    p_eng.add_argument("--vex", default=None, metavar="JSON",
                       help="VEX triage file; not_affected/fixed records move "
                            "to an appendix instead of counting as findings")
    p_eng.add_argument("--config", default=None,
                       help="campaign.toml, for engagement id / authorization "
                            "/ sponsor")
    p_eng.add_argument("--client", default=None)
    p_eng.add_argument("--assessor", default=None)
    p_eng.add_argument("--title", default=None)
    p_eng.add_argument("--period", default=None, metavar="DATES",
                       help='e.g. "2026-11-01 to 2026-11-14"')
    p_eng.add_argument("--engagement-id", default=None)
    p_eng.add_argument("--authorization", default=None,
                       help="authorization / RoE reference")
    p_eng.add_argument("--scope", action="append", default=None,
                       help="in-scope item (repeatable)")
    p_eng.add_argument("--format", default="html",
                       choices=["html", "md", "json"])
    p_eng.add_argument("--no-group", action="store_true",
                       help="list every CVE as its own finding (verbose)")
    p_eng.add_argument("--out", default=None, help="write here instead of stdout")
    p_eng.set_defaults(func=cmd_engagement)

    # --- scope and authorization ------------------------------------------

    p_scope = sub.add_parser(
        "scope",
        help="validate the authorization/scope file, or ask it about a target")
    p_scope.add_argument("file", nargs="?", default=None, metavar="TOML",
                         help="the scope file to validate")
    p_scope.add_argument("--init", default=None, metavar="PATH",
                         help="write a commented scope template and exit")
    p_scope.add_argument("--target", action="append", default=None,
                         metavar="URL",
                         help="ask whether this target is in scope "
                              "(repeatable); exit 1 if any is refused")
    p_scope.add_argument("--json", default=None, metavar="JSON",
                         help="write the scope and its decisions here")
    p_scope.set_defaults(func=cmd_scope)

    p_probe = sub.add_parser(
        "probe",
        help="benign injection susceptibility probe of your own AI endpoint "
             "(requires an authorised scope file)")
    p_probe.add_argument("--scope", required=True, metavar="TOML",
                         help="authorization/scope file; the probe target "
                              "must be listed in it or the run is refused")
    p_probe.add_argument("--dry-run", action="store_true",
                         help="print exactly what would be sent, send nothing")
    p_probe.add_argument("--fail-on", default=None, metavar="SEVERITY",
                         help="exit 1 if observed susceptibility is >= this")
    p_probe.add_argument("--json", default=None, metavar="JSON",
                         help="write the full report here")
    p_probe.set_defaults(func=cmd_probe)

    # --- the one-command assessment ---------------------------------------

    p_doctor = sub.add_parser(
        "doctor",
        help="check this machine's dependencies before an engagement, "
             "not during one")
    p_doctor.add_argument("--profile", default=None, metavar="TOML",
                          help="check only what this assessment profile "
                               "needs")
    p_doctor.add_argument("--offline", action="store_true",
                          help="skip the network probes; they are then "
                               "reported as NOT CHECKED, never as healthy")
    p_doctor.add_argument("--timeout", type=int, default=None, metavar="SECS",
                          help="per-probe timeout (default 8)")
    p_doctor.add_argument("--json", default=None, metavar="PATH",
                          help="also write the result as JSON")
    p_doctor.set_defaults(func=cmd_doctor)

    p_assess = sub.add_parser(
        "assess",
        help="run every configured stage and produce the report (one command)")
    p_assess.add_argument("--profile", default=None, metavar="TOML",
                          help="assessment profile (see --init)")
    p_assess.add_argument("--init", default=None, metavar="TOML",
                          help="write a commented profile template and exit")
    p_assess.add_argument("--deps", action="append", default=None,
                          metavar="DIR", help="scan dependencies here")
    p_assess.add_argument("--sbom", action="append", default=None,
                          metavar="FILE", help="scan this CycloneDX/SPDX SBOM")
    p_assess.add_argument("--code", action="append", default=None,
                          metavar="DIR", help="static-analyse this tree")
    p_assess.add_argument("--ai", action="append", default=None,
                          metavar="DIR", help="assess AI/ML code and model "
                                              "artifacts in this tree")
    p_assess.add_argument("--exclude", action="append", default=None,
                          metavar="GLOB",
                          help="exclude paths from the code and AI scans")
    p_assess.add_argument("--history", action="append", default=None,
                          metavar="DIR",
                          help="scan this repository's git history for "
                               "committed secrets")
    p_assess.add_argument("--probe-scope", default=None, metavar="TOML",
                          help="scope file authorising a benign live probe "
                               "of an AI endpoint")
    p_assess.add_argument("--domain", action="append", default=None,
                          help="audit this domain's email posture")
    p_assess.add_argument("--no-fetch", action="store_true",
                          help="email stage: DNS only, skip the MTA-STS fetch")
    p_assess.add_argument("--hits", default=None, metavar="DB",
                          help="awareness results database")
    p_assess.add_argument("--detect", action="store_true",
                          help="also emit Sigma rules, ATT&CK layer, checklist")
    p_assess.add_argument("--vex", default=None, metavar="JSON",
                          help="VEX triage file")
    p_assess.add_argument("--config", default=None,
                          help="campaign.toml, for engagement id / authorization")
    p_assess.add_argument("--client", default=None)
    p_assess.add_argument("--title", default=None)
    p_assess.add_argument("--period", default=None)
    p_assess.add_argument("--assessor", default=None)
    p_assess.add_argument("--engagement-id", default=None)
    p_assess.add_argument("--authorization", default=None)
    p_assess.add_argument("--scope", action="append", default=None)
    p_assess.add_argument("--format", action="append", default=None,
                          choices=["html", "md", "json"],
                          help="report format (repeatable; default html)")
    p_assess.add_argument("--out-dir", default=None,
                          help="where artifacts and the report go")
    p_assess.add_argument("--baseline", default=None, metavar="PATH",
                          help="gate on findings new since this baseline")
    p_assess.add_argument("--fail-on", default=None, metavar="SEVERITY",
                          help="exit 1 if findings reach this severity")
    p_assess.add_argument("--workers", type=int, default=None)
    p_assess.add_argument("--quiet", "-q", action="store_true")
    p_assess.add_argument("--no-ledger", action="store_true",
                          help="omit the assurance ledger from the summary")
    p_assess.add_argument("--no-preflight", action="store_true",
                          help="skip the dependency check this run starts "
                               "with (see `coldlight doctor`)")
    p_assess.set_defaults(func=cmd_assess)

    p_assurance = sub.add_parser(
        "assurance",
        help="what an assessment examined — and what nobody looked at")
    p_assurance.add_argument("source", nargs="?", default="assessment",
                             metavar="DIR",
                             help="an assess output directory (default: "
                                  "assessment)")
    p_assurance.add_argument("--format", default="text",
                             choices=["text", "md", "json"])
    p_assurance.add_argument("--json", default=None,
                             help="also write the ledger here")
    p_assurance.add_argument("--require-complete", action="store_true",
                             help="exit 1 if any in-scope class was not "
                                  "examined")
    p_assurance.set_defaults(func=cmd_assurance)

    # --- verifiable results -----------------------------------------------

    p_attest = sub.add_parser(
        "attest", help="sign an assessment, and verify a signed one")
    attest_sub = p_attest.add_subparsers(dest="attest_action", required=True)

    p_acreate = attest_sub.add_parser(
        "create", help="write an in-toto attestation over the report + inputs")
    p_acreate.add_argument("source", nargs="?", default="assessment",
                           metavar="DIR")
    p_acreate.add_argument("--sign-with", default=None,
                           choices=["gpg", "openssl", "hmac"],
                           help="delegate signing to this tool")
    p_acreate.add_argument("--key", default=None,
                           help="gpg key id, or path to an OpenSSL private key")
    p_acreate.add_argument("--passphrase-env", default=None, metavar="VAR",
                           help="env var holding the OpenSSL key passphrase "
                                "(read by openssl itself, never by ColdLight)")
    p_acreate.add_argument("--hmac-env", default=None, metavar="VAR",
                           help="env var holding the shared secret (hmac "
                                "backend only)")
    p_acreate.add_argument("--dry-run", action="store_true",
                           help="print the signing command without running it")
    p_acreate.set_defaults(func=cmd_attest_create)

    p_averify = attest_sub.add_parser(
        "verify", help="recompute every digest and check the signature")
    p_averify.add_argument("source", nargs="?", default="assessment",
                           metavar="DIR")
    p_averify.add_argument("--key", default=None,
                           help="public key for OpenSSL verification")
    p_averify.add_argument("--hmac-env", default=None, metavar="VAR")
    p_averify.add_argument("--require-signature", action="store_true",
                           help="exit 1 unless a signature verifies")
    p_averify.add_argument("--json", default=None)
    p_averify.set_defaults(func=cmd_attest_verify)

    return ap


def main(argv: list[str] | None = None) -> int:
    # Feed text (CISA KEV especially) contains typographic quotes that the
    # default Windows console codepage mangles.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
