#!/usr/bin/env python3
"""
Read http(s) links from README.md. Skip any host listed in deal-scan-blocklist.txt
(no HTTP request — those sites have refused scans before).

For each remaining unique URL: fetch once. On 403, append that host to the blocklist
and stop touching that host forever. On success, send trimmed page text to GitHub Models
and ask for sale descriptions + links.

Writes deal-scan-test.md: only columns Description | Link (no status codes, no keyword hits).

Env:
  GITHUB_TOKEN  — required (repo workflow or local `gh auth token`)
  DEALS_MODEL   — optional, default openai/gpt-4.1

Usage (repo root):
  export GITHUB_TOKEN=...
  python3 scripts/deal_scan_test.py
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
README_DEFAULT = ROOT / "README.md"
OUT_DEFAULT = ROOT / "deal-scan-test.md"
BLOCKLIST_DEFAULT = ROOT / "deal-scan-blocklist.txt"

LINK_RE = re.compile(r"\[[^\]]*\]\((https?://[^\s\)]+)\)", re.IGNORECASE)

GITHUB_MODELS_URL = "https://models.github.ai/inference/chat/completions"
HTTP_USER_AGENT = "Infosec-Deals-scan/1.0 (+https://github.com/davidalex89/Infosec-Deals)"
MAX_BYTES = 500_000
FETCH_TIMEOUT = 25
MAX_TEXT_FOR_MODEL = 28_000
MODEL_SLEEP_SEC = 0.6


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


def normalize_host(netloc: str) -> str:
    n = netloc.lower().split("@")[-1]
    if ":" in n:
        n = n.split(":")[0]
    if n.startswith("www."):
        n = n[4:]
    return n


def load_blocklist(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    out: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.add(normalize_host(line))
    return out


def add_host_to_blocklist(path: Path, netloc: str) -> None:
    host = normalize_host(netloc)
    if not host:
        return
    cur = load_blocklist(path)
    if host in cur:
        return
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"{host}\n")
    print(f"Added to blocklist (no future requests): {host}", file=sys.stderr)


def extract_links(md: str) -> list[str]:
    seen: dict[str, None] = {}
    for m in LINK_RE.finditer(md):
        u = m.group(1).rstrip(").,;")
        if u not in seen:
            seen[u] = None
    return list(seen.keys())


def http_post_json(url: str, headers: dict, payload: dict) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "User-Agent": HTTP_USER_AGENT,
            **headers,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        body = resp.read().decode("utf-8")
        return json.loads(body) if body.strip() else {}


def fetch(url: str) -> tuple[int | None, str, str]:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": HTTP_USER_AGENT, "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
            code = resp.getcode()
            raw = resp.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raw = raw[:MAX_BYTES]
            charset = resp.headers.get_content_charset() or "utf-8"
            text = raw.decode(charset, errors="replace")
            return code, text, ""
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")[:5000]
        except Exception:
            body = ""
        return e.code, body, str(e)
    except Exception as e:
        return None, "", str(e)


def _parse_json_object(content: str) -> dict:
    text = content.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end > start:
            return json.loads(text[start : end + 1])
        raise


def extract_deals_with_model(token: str, model: str, page_url: str, page_text: str) -> list[dict]:
    snippet = page_text[:MAX_TEXT_FOR_MODEL]
    if len(page_text) > MAX_TEXT_FOR_MODEL:
        snippet += "\n\n[…truncated…]"
    system = (
        "You extract active promotional offers from webpage text for a curated infosec/tech deals list. "
        "Respond with ONLY valid JSON: {\"deals\":[{\"description\":\"short plain English\",\"link\":\"https://...\"}]} . "
        "Use an absolute https URL for link when the page names a specific offer URL; otherwise use the page URL given. "
        "If there is no clear current sale/discount/promo/coupon, return {\"deals\":[]}. "
        "At most 3 deals per page. No markdown, no commentary outside JSON."
    )
    user = f"Page URL: {page_url}\n\nPage text:\n{snippet}"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": 0.2,
        "max_tokens": 1200,
    }
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
    }
    data = http_post_json(GITHUB_MODELS_URL, headers, payload)
    content = data["choices"][0]["message"]["content"]
    parsed = _parse_json_object(content)
    deals = parsed.get("deals", [])
    out: list[dict] = []
    for d in deals[:3]:
        if not isinstance(d, dict):
            continue
        desc = str(d.get("description", "")).strip()
        link = str(d.get("link", "")).strip() or page_url
        if desc:
            out.append({"description": desc, "link": link})
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--readme", type=Path, default=README_DEFAULT)
    ap.add_argument("--out", type=Path, default=OUT_DEFAULT)
    ap.add_argument("--blocklist", type=Path, default=BLOCKLIST_DEFAULT)
    args = ap.parse_args()

    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not token:
        print("GITHUB_TOKEN is required for GitHub Models.", file=sys.stderr)
        return 1

    model = os.environ.get("DEALS_MODEL", "openai/gpt-4.1").strip()

    if not args.readme.is_file():
        print(f"Missing {args.readme}", file=sys.stderr)
        return 1

    blocklist = load_blocklist(args.blocklist)
    md = args.readme.read_text(encoding="utf-8")
    urls = extract_links(md)

    rows: list[tuple[str, str]] = []
    skipped_blocklist = 0
    skipped_fetch_fail = 0
    newly_blocked = 0

    for url in urls:
        p = urlparse(url)
        if p.scheme not in ("http", "https") or not p.netloc:
            continue
        host = normalize_host(p.netloc)
        if host in blocklist:
            skipped_blocklist += 1
            continue

        code, body, err = fetch(url)
        if code == 403:
            add_host_to_blocklist(args.blocklist, p.netloc)
            blocklist.add(host)
            newly_blocked += 1
            continue

        if code is None or (code and code >= 400):
            print(f"Skip (no model): {url} — {code} {err[:80]}", file=sys.stderr)
            skipped_fetch_fail += 1
            continue

        plain = html_to_text(body)
        try:
            deals = extract_deals_with_model(token, model, url, plain)
        except Exception as e:
            print(f"Model error for {url}: {e}", file=sys.stderr)
            skipped_fetch_fail += 1
            time.sleep(MODEL_SLEEP_SEC)
            continue

        for d in deals:
            rows.append((d["description"], d["link"]))
        time.sleep(MODEL_SLEEP_SEC)

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Deal scan (GitHub Models)",
        "",
        f"Generated **{ts}** from links in `{args.readme.name}`.",
        "",
        f"Hosts in `{args.blocklist.name}` are **never requested** (403 history). ",
        f"This run: **{skipped_blocklist}** URL(s) skipped via blocklist, **{newly_blocked}** new host(s) added after 403.",
        "",
        "| Description | Link |",
        "|-------------|------|",
    ]

    if not rows:
        lines.append("| *No promotional offers extracted this run.* | — |")
    else:
        for desc, link in rows:
            safe = desc.replace("|", "/")
            lines.append(f"| {safe} | [link]({link}) |")

    args.out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(
        f"Wrote {args.out} — {len(rows)} deal row(s); "
        f"{skipped_blocklist} skipped (blocklist); {skipped_fetch_fail} fetch/model skips; {newly_blocked} new 403→blocklist.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
