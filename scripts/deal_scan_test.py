#!/usr/bin/env python3
"""
Extract http(s) links from README.md, dedupe by site origin (scheme + host → /),
fetch each homepage, and look for crude sale/discount signals in the HTML text.
Origins that return 403 (or time out) are omitted from the report.

Writes deal-scan-test.md in the repo root. No dependencies beyond stdlib.

Usage (from repo root):
  python3 scripts/deal_scan_test.py
  python3 scripts/deal_scan_test.py --readme path/to/README.md --out deal-scan-test.md
"""

from __future__ import annotations

import argparse
import html
import re
import sys
import urllib.error
import urllib.request
from collections import OrderedDict
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse, urlunparse

ROOT = Path(__file__).resolve().parents[1]
README_DEFAULT = ROOT / "README.md"
OUT_DEFAULT = ROOT / "deal-scan-test.md"

LINK_RE = re.compile(r"\[[^\]]*\]\((https?://[^\s\)]+)\)", re.IGNORECASE)

# Crude signals — false positives/negatives expected; this is a test sweep.
KEYWORD_CHECKS: list[tuple[str, re.Pattern[str]]] = [
    ("black friday", re.compile(r"\bblack\s+friday\b", re.I)),
    ("cyber monday", re.compile(r"\bcyber\s+monday\b", re.I)),
    ("sale", re.compile(r"\bsale\b", re.I)),
    ("discount", re.compile(r"\bdiscount\b", re.I)),
    ("promo", re.compile(r"\bpromo(tion| code)?\b", re.I)),
    ("coupon", re.compile(r"\bcoupon\b", re.I)),
    ("% off", re.compile(r"(\b%\s*off\b|\d+\s*%\s*off|\bsave\s+\d+\s*%)", re.I)),
    ("bundle / for $", re.compile(r"\bx\s+for\s+\$", re.I)),
]

USER_AGENT = "Infosec-Deals-scan-test/1.0 (+https://github.com/davidalex89/Infosec-Deals)"
MAX_BYTES = 500_000
TIMEOUT_SEC = 20


class _Stripper(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._chunks: list[str] = []

    def handle_data(self, data: str) -> None:
        if data.strip():
            self._chunks.append(data)

    def text(self) -> str:
        return " ".join(self._chunks)


def html_to_text(raw: str) -> str:
    p = _Stripper()
    try:
        p.feed(raw)
        p.close()
        t = p.text()
    except Exception:
        t = re.sub(r"<[^>]+>", " ", raw)
    t = html.unescape(t)
    t = re.sub(r"\s+", " ", t).strip()
    return t


def extract_links(md: str) -> list[str]:
    return [m.group(1).rstrip(").,;") for m in LINK_RE.finditer(md)]


def origin_url(url: str) -> str | None:
    try:
        p = urlparse(url)
        if p.scheme not in ("http", "https") or not p.netloc:
            return None
        netloc = p.netloc.split("@")[-1].lower()
        if ":" in netloc and netloc.count(":") == 1:
            host, port = netloc.rsplit(":", 1)
            if port.isdigit() and host:
                netloc = f"{host}:{port}"
        scheme = p.scheme.lower()
        return urlunparse((scheme, netloc, "/", "", "", ""))
    except Exception:
        return None


def dedupe_origins(urls: list[str]) -> OrderedDict[str, str]:
    """Map normalized netloc (host[:port]) -> preferred origin URL (https wins)."""
    by_host: dict[str, tuple[str, int]] = {}
    for u in urls:
        o = origin_url(u)
        if not o:
            continue
        p = urlparse(o)
        host = p.netloc
        score = 1 if p.scheme == "https" else 0
        prev = by_host.get(host)
        if prev is None or score > prev[1]:
            by_host[host] = (o, score)
    out: OrderedDict[str, str] = OrderedDict()
    for host in sorted(by_host.keys()):
        out[host] = by_host[host][0]
    return out


def fetch(url: str) -> tuple[int | None, str, str]:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SEC) as resp:
            code = resp.getcode()
            raw = resp.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raw = raw[:MAX_BYTES]
            charset = "utf-8"
            ct = resp.headers.get_content_charset()
            if ct:
                charset = ct
            text = raw.decode(charset, errors="replace")
            return code, text, ""
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:5000]
        return e.code, body, str(e)
    except Exception as e:
        return None, "", str(e)


def find_hits(plain: str) -> list[str]:
    return [label for label, pat in KEYWORD_CHECKS if pat.search(plain)]


def _is_timeout_error(err: str) -> bool:
    e = err.lower()
    return "timed out" in e or "timeout" in e


def main() -> int:
    ap = argparse.ArgumentParser(description="Homepage sale-keyword test scan for README links.")
    ap.add_argument("--readme", type=Path, default=README_DEFAULT)
    ap.add_argument("--out", type=Path, default=OUT_DEFAULT)
    args = ap.parse_args()

    if not args.readme.is_file():
        print(f"Missing README: {args.readme}", file=sys.stderr)
        return 1

    md = args.readme.read_text(encoding="utf-8")
    links = extract_links(md)
    origins = dedupe_origins(links)

    lines = [
        "# Deal scan test (homepage / origin only)",
        "",
        f"Generated **{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}** from links in `{args.readme.name}`.",
        "",
        "For each **unique site** (`scheme://host/`), we fetch the **root path** only — not the specific deal URL from the README. ",
        "Keyword hits are **noisy** (banners, footers, unrelated copy). Use this as a quick smoke test, not ground truth.",
        "",
        "Origins that return **403 Forbidden** (or fetch **timeout**) are **not listed** — we do not treat those homepages as scanned.",
        "",
        "| Origin fetched | HTTP | Keyword-ish hits | Notes |",
        "|----------------|------|------------------|-------|",
    ]

    listed = 0
    n_forbidden = 0
    n_timeout = 0

    for _host, origin in origins.items():
        code, body, err = fetch(origin)
        if code == 403:
            n_forbidden += 1
            continue
        if err and not body:
            if _is_timeout_error(err):
                n_timeout += 1
                continue
            lines.append(f"| `{origin}` | — | — | {err[:120].replace('|', '/')} |")
            listed += 1
            continue
        plain = html_to_text(body) if body else ""
        hits = find_hits(plain)
        hit_cell = ", ".join(f"`{h}`" for h in hits[:8]) if hits else "—"
        if len(hits) > 8:
            hit_cell += f" (+{len(hits) - 8} more)"
        code_s = str(code) if code is not None else "—"
        note = err[:100] if err else ""
        lines.append(f"| `{origin}` | {code_s} | {hit_cell} | {note.replace('|', '/')} |")
        listed += 1

    stats = (
        f"**Summary:** {listed} origin(s) in table, {n_forbidden} skipped (403), {n_timeout} skipped (timeout), "
        f"{len(origins)} unique origins from {len(links)} README links."
    )
    for i, line in enumerate(lines):
        if line.startswith("| Origin fetched |"):
            lines.insert(i, "")
            lines.insert(i, stats)
            break

    args.out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {args.out} ({listed} listed, {n_forbidden}×403 skipped, {n_timeout}×timeout skipped).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
