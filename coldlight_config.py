#!/usr/bin/env python3
"""
Shared campaign configuration for the ColdLight awareness-test framework.

One place defines what a campaign is, how it's loaded, and how it's validated.
Both the CLI (reads campaign.toml) and the payload (reads a baked/external
JSON copy at runtime) use this module, so they can never drift apart.

Dependency-free: the CLI path uses the stdlib `tomllib` (Python 3.11+); the
payload path uses `json` only.
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

# Single source of truth for the version. This module is imported by both the
# CLI and the frozen payload, so it is the one place every component can read.
# Keep it in step with [project].version in pyproject.toml.
__version__ = "1.5.0"

# Any config value containing one of these is treated as "not filled in yet".
PLACEHOLDER_MARKERS = ("CHANGE-ME",)

BAKED_CONFIG_NAME = "_baked_config.json"      # bundled inside the frozen exe
EXTERNAL_CONFIG_NAME = "campaign.json"        # optional override next to the exe


@dataclass
class CampaignConfig:
    """Everything a single awareness-test campaign needs."""

    engagement_id: str = "CHANGE-ME-ENGAGEMENT-ID"
    authorization_reference: str = "CHANGE-ME"
    sponsor: str = "the security team"
    lure_filename: str = "coldlight_awareness.exe"
    show_gui: bool = True
    open_training_page: bool = False
    collector_url: str = ""
    collector_token: str = ""
    message_text: str = ""  # empty -> use the built-in default message
    safelist: list[str] = field(default_factory=list)  # opt-out / excluded identities

    @classmethod
    def from_dict(cls, data: dict) -> "CampaignConfig":
        """Build from a flat dict, ignoring unknown keys and filling defaults."""
        fields = {f for f in cls().__dict__}
        clean = {k: v for k, v in (data or {}).items() if k in fields}
        return cls(**clean)

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# CLI side: load from a human-edited TOML file
# ---------------------------------------------------------------------------

def load_config(path: str | Path) -> CampaignConfig:
    """Load a campaign.toml into a CampaignConfig (flattens the TOML sections)."""
    import tomllib  # stdlib, 3.11+

    raw = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    campaign = raw.get("campaign", {})
    payload = raw.get("payload", {})
    collector = raw.get("collector", {})
    message = raw.get("message", {})
    safelist = raw.get("safelist", {})

    flat = {
        "engagement_id": campaign.get("engagement_id"),
        "authorization_reference": campaign.get("authorization_reference"),
        "sponsor": campaign.get("sponsor"),
        "lure_filename": payload.get("lure_filename"),
        "show_gui": payload.get("show_gui"),
        "open_training_page": payload.get("open_training_page"),
        "collector_url": collector.get("url"),
        "collector_token": collector.get("token"),
        "message_text": message.get("text"),
        "safelist": safelist.get("patterns"),
    }
    # Drop keys whose value is None so dataclass defaults apply.
    flat = {k: v for k, v in flat.items() if v is not None}
    return CampaignConfig.from_dict(flat)


def validate(cfg: CampaignConfig) -> tuple[list[str], list[str]]:
    """Return (errors, warnings). Errors should block a production build."""
    errors: list[str] = []
    warnings: list[str] = []

    def is_placeholder(value: str) -> bool:
        return (not value) or any(m in value for m in PLACEHOLDER_MARKERS)

    if is_placeholder(cfg.engagement_id):
        errors.append("engagement_id is empty or still a CHANGE-ME placeholder")
    if is_placeholder(cfg.authorization_reference):
        errors.append("authorization_reference is empty or still a CHANGE-ME placeholder")
    if not cfg.sponsor or is_placeholder(cfg.sponsor):
        warnings.append("sponsor is empty or a placeholder")
    if not cfg.lure_filename.lower().endswith(".exe"):
        warnings.append("lure_filename does not end in .exe")

    url = (cfg.collector_url or "").strip()
    if url:
        if not url.lower().startswith(("http://", "https://")):
            errors.append("collector_url must start with http:// or https://")
        elif url.lower().startswith("http://"):
            warnings.append("collector_url uses http:// (unencrypted) — prefer https://")
        if not cfg.collector_token:
            warnings.append("collector_url is set but collector_token is empty — "
                            "the collector will reject unauthenticated hits")

    return errors, warnings


# ---------------------------------------------------------------------------
# Payload side: resolve config at runtime (external override -> baked -> default)
# ---------------------------------------------------------------------------

def run_dir() -> Path:
    """Folder the script/exe is running from (reveals the USB drive)."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def load_runtime_config() -> tuple[CampaignConfig, str]:
    """Resolve the active config and report where it came from.

    Precedence:
      1. `campaign.json` sitting next to the exe (lets ops tweak on the USB
         without a rebuild),
      2. `_baked_config.json` bundled into the frozen exe at build time,
      3. built-in safe defaults.
    """
    external = run_dir() / EXTERNAL_CONFIG_NAME
    if external.is_file():
        try:
            data = json.loads(external.read_text(encoding="utf-8"))
            return CampaignConfig.from_dict(data), f"external ({external.name})"
        except Exception:
            pass

    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        baked = Path(meipass) / BAKED_CONFIG_NAME
        if baked.is_file():
            try:
                data = json.loads(baked.read_text(encoding="utf-8"))
                return CampaignConfig.from_dict(data), "baked"
            except Exception:
                pass

    return CampaignConfig(), "defaults"
