#!/usr/bin/env python3
"""
QR-code drop vector for the ColdLight awareness test.

Generates a printable SVG QR code that points at the collector's click-tracking
landing page (`/land?c=<campaign>&t=<tag>`). Stick it on a poster/flyer instead
of (or alongside) a USB stick: scanning it records an awareness "click" and shows
the training page. Benign — the landing page never asks for credentials.

SVG output needs no image libraries; computing the QR matrix needs `qrcode`
(`pip install qrcode`).
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlencode, urlparse


def make_url(base_url: str, campaign: str, tag: str = "") -> str:
    """Build the landing URL with campaign (c) and optional tag (t) params."""
    params = {"c": campaign}
    if tag:
        params["t"] = tag
    sep = "&" if urlparse(base_url).query else "?"
    return f"{base_url}{sep}{urlencode(params)}"


def qr_matrix(data: str, error: str = "M") -> list[list[bool]]:
    """Return the QR code as a matrix of booleans (True = dark module)."""
    import qrcode  # optional dep

    qr = qrcode.QRCode(
        error_correction=getattr(qrcode.constants, f"ERROR_CORRECT_{error}"),
        box_size=1, border=0,
    )
    qr.add_data(data)
    qr.make(fit=True)
    return qr.get_matrix()


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def matrix_to_svg(matrix: list[list[bool]], scale: int = 8, border: int = 4,
                  caption: str = "") -> str:
    """Render a QR matrix to a standalone SVG string (black on white)."""
    n = len(matrix)
    size = (n + border * 2) * scale
    cap_h = 28 if caption else 0
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size + cap_h}" '
        f'viewBox="0 0 {size} {size + cap_h}">',
        f'<rect width="{size}" height="{size + cap_h}" fill="#ffffff"/>',
    ]
    for y, row in enumerate(matrix):
        for x, cell in enumerate(row):
            if cell:
                parts.append(
                    f'<rect x="{(x + border) * scale}" y="{(y + border) * scale}" '
                    f'width="{scale}" height="{scale}" fill="#000000"/>'
                )
    if caption:
        parts.append(
            f'<text x="{size / 2}" y="{size + 18}" text-anchor="middle" '
            f'font-family="sans-serif" font-size="14" fill="#000000">{_esc(caption)}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


def write_qr_svg(base_url: str, campaign: str, tag: str = "", out: str | Path = "qr.svg",
                 caption: str | None = None, scale: int = 8) -> tuple[str, str]:
    """Build the URL, render the QR to SVG, write it. Returns (url, out_path)."""
    url = make_url(base_url, campaign, tag)
    svg = matrix_to_svg(qr_matrix(url), scale=scale,
                        caption=caption if caption is not None else campaign)
    Path(out).write_text(svg, encoding="utf-8")
    return url, str(out)
