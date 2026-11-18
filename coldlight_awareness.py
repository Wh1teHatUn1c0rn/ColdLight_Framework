#!/usr/bin/env python3
"""
ColdLight USB Awareness Test -- benign "found USB" payload.

PURPOSE
-------
Measure how many people plug in and *run* a file from an unknown USB stick
during an AUTHORIZED security-awareness exercise, then teach them in the moment.

When executed it:
  1. Records that it was run (timestamp, host, user, where it ran from).
  2. Writes that record to a local log next to the executable (on the USB) and
     to the system temp dir as a fallback.
  3. Optionally reports the hit to the engagement's collection server (opt-in;
     disabled unless a collector URL is configured).
  4. Shows the person a short security-awareness message.

Its behaviour is driven entirely by a campaign config (see campaign.toml /
coldlight_config.py), resolved at runtime from an external file next to the exe,
an embedded baked copy, or safe defaults -- in that order.

It deliberately does NOT, and must not be made to:
  - install anything, create persistence, or modify system settings
  - execute shellcode or download/run further code
  - read the user's files, capture keystrokes, or collect credentials
  - hide itself or evade security tooling

Run `python coldlight_awareness.py --dry-run` to see exactly what it would record
without writing logs, beaconing, or showing a window.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import platform
import socket
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import coldlight_safelist
from coldlight_config import CampaignConfig, load_runtime_config, run_dir

LOG_FILENAME = "coldlight_awareness_hits.jsonl"
TRAINING_PAGE = "awareness_message.html"  # relative to the exe, or a URL


def collect_context(cfg: CampaignConfig) -> dict:
    """Collect the minimal, non-sensitive info needed to report participation."""
    return {
        "engagement_id": cfg.engagement_id,
        "run_id": uuid.uuid4().hex,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "hostname": socket.gethostname(),
        "username": getpass.getuser(),
        "os": f"{platform.system()} {platform.release()}",
        "ran_from": str(run_dir()),
    }


def write_local_log(record: dict) -> list[str]:
    """Append the record to a log next to the exe and in the temp dir.

    Returns the paths actually written. Never raises -- a logging failure must
    not crash the awareness message.
    """
    line = json.dumps(record) + "\n"
    written: list[str] = []
    candidates = [
        run_dir() / LOG_FILENAME,                          # on the USB itself
        Path(os.environ.get("TEMP", ".")) / LOG_FILENAME,  # local fallback
    ]
    for path in candidates:
        try:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line)
            written.append(str(path))
        except Exception:
            pass
    return written


def beacon(record: dict, collector_url: str, collector_token: str = "") -> bool:
    """Optionally POST the record to the engagement collector. Opt-in only."""
    if not collector_url:
        return False
    try:
        import urllib.request

        data = json.dumps(record).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if collector_token:
            headers["Authorization"] = f"Bearer {collector_token}"
        req = urllib.request.Request(
            collector_url,
            data=data,
            headers=headers,
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5)  # noqa: S310 (trusted, configured URL)
        return True
    except Exception:
        return False


def awareness_text(cfg: CampaignConfig) -> str:
    if cfg.message_text.strip():
        try:
            return cfg.message_text.format(
                sponsor=cfg.sponsor,
                authorization_reference=cfg.authorization_reference,
                engagement_id=cfg.engagement_id,
            )
        except Exception:
            return cfg.message_text
    return (
        "==============================================================\n"
        "              SECURITY AWARENESS TEST\n"
        "==============================================================\n\n"
        "You just opened a program from a USB device that was not yours.\n\n"
        "In a real attack, double-clicking that file could have installed\n"
        "malware, stolen your passwords, or given an attacker control of\n"
        "this computer -- silently.\n\n"
        "Good news: this was a harmless test. Nothing was installed and\n"
        "nothing was changed on this machine.\n\n"
        f"  - Run by : {cfg.sponsor}\n"
        f"  - Authorization: {cfg.authorization_reference}\n"
        f"  - Engagement: {cfg.engagement_id}\n\n"
        "What to do next time:\n"
        "  - Do NOT plug in USB devices you find or receive unexpectedly.\n"
        "  - Hand them to IT / Security instead.\n"
        "  - Report this test if you'd like to -- you're not in trouble.\n\n"
        "Thanks for helping keep us secure.\n"
        "==============================================================\n"
    )


def show_message(cfg: CampaignConfig) -> None:
    text = awareness_text(cfg)
    print(text)

    if cfg.show_gui:
        try:
            import tkinter as tk
            from tkinter import messagebox

            root = tk.Tk()
            root.withdraw()
            messagebox.showwarning("Security Awareness Test", text)
            root.destroy()
        except Exception:
            pass  # headless / no Tk -> console output already shown

    if cfg.open_training_page:
        try:
            import webbrowser

            target = TRAINING_PAGE
            if "://" not in target:
                target = (run_dir() / TRAINING_PAGE).as_uri()
            webbrowser.open(target)
        except Exception:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description="ColdLight USB awareness-test payload.")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the record and resolved config, then exit. No logging, "
             "no network, no pop-up.",
    )
    args = parser.parse_args()

    cfg, source = load_runtime_config()
    record = collect_context(cfg)
    excluded = bool(cfg.safelist) and coldlight_safelist.matches(
        cfg.safelist, record["hostname"], record["username"]
    )

    if args.dry_run:
        print(f"[dry-run] config source: {source}")
        print(f"[dry-run] sponsor: {cfg.sponsor}")
        print(f"[dry-run] collector configured: {bool(cfg.collector_url)}")
        print(f"[dry-run] safe-listed (would suppress): {excluded}")
        print("[dry-run] would record:")
        print(json.dumps(record, indent=2))
        return 0

    if excluded:
        # Opt-out: this host/user is on the safe-list. Do nothing, record nothing.
        print("[coldlight] host/user is on the safe-list; suppressed.")
        return 0

    logs = write_local_log(record)
    sent = beacon(record, cfg.collector_url, cfg.collector_token)

    show_message(cfg)

    print(f"[coldlight] config source: {source}")
    print(f"[coldlight] logged to: {logs or 'nowhere (all writes failed)'}")
    print(f"[coldlight] beacon sent: {sent}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
