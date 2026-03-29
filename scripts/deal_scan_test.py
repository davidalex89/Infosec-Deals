#!/usr/bin/env python3
"""
Read http(s) links from README.md. Skip hosts in deal-scan-blocklist.txt (no request).

For each URL: fetch HTML, strip to text, then either:
  • Keyword heuristics → **Yes** / **No** (default), or
  • Local **Ollama** (`USE_OLLAMA=1`) → JSON {sale, rationale} for smarter yes/no.

If Ollama errors, falls back to heuristics for that row (noted in output).

Output: deal-scan.local.md (gitignored). Options: --out, --limit N.

Usage (repo root):
  python3 scripts/deal_scan_test.py
  USE_OLLAMA=1 OLLAMA_MODEL=llama3.2 python3 scripts/deal_scan_test.py --limit 5
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
OUT_DEFAULT = ROOT / "deal-scan.local.md"
BLOCKLIST_DEFAULT = ROOT / "deal-scan-blocklist.txt"

LINK_RE = re.compile(r"\[[^\]]*\]\((https?://[^\s\)]+)\)", re.IGNORECASE)
HTTP_USER_AGENT = "Infosec-Deals-scan/1.0 (+https://github.com/davidalex89/Infosec-Deals)"
MAX_BYTES = 500_000
FETCH_TIMEOUT = 25
MAX_TEXT_OLLAMA = 14_000
OLLAMA_CHAT_TIMEOUT = 300
OLLAMA_SLEEP_SEC = 0.4

OLLAMA_SYSTEM = (
    "You classify whether a web page's visible text describes an active promotional offer "
    "(sale, discount, coupon code, limited-time deal, bundle pricing, holiday promo). "
    "Marketing fluff without a concrete offer → sale false. "
    "Reply with ONLY valid JSON: {\"sale\": true or false, \"rationale\": \"<=20 words\"}"
)

# If any pattern matches (case-insensitive on plain text), we report **Yes**.
SALE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("black friday", re.compile(r"\bblack\s+friday\b", re.I)),
    ("cyber monday", re.compile(r"\bcyber\s+monday\b", re.I)),
    ("sale", re.compile(r"\bsale\b", re.I)),
    ("discount", re.compile(r"\bdiscount\b", re.I)),
    ("promo", re.compile(r"\bpromo(tion| code)?\b", re.I)),
    ("coupon", re.compile(r"\bcoupon\b", re.I)),
    ("code", re.compile(r"\b(promo|coupon)\s+code\b", re.I)),
    ("% off", re.compile(r"\d+\s*%\s*off|\b%\s*off\b", re.I)),
    ("save %", re.compile(r"\bsave\s+\d+\s*%", re.I)),
    ("off sitewide", re.compile(r"\boff\s+sitewide\b", re.I)),
    ("limited time", re.compile(r"\blimited\s+time\s+(offer|deal|sale)\b", re.I)),
]


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


def detect_sale(plain: str) -> tuple[bool, list[str]]:
    hits = [name for name, pat in SALE_PATTERNS if pat.search(plain)]
    return (len(hits) > 0), hits


def _truthy_env(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _coerce_bool(v: object) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in ("true", "yes", "1")
    return bool(v)


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


def http_post_json(url: str, payload: dict, timeout: int) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"User-Agent": HTTP_USER_AGENT, "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
        return json.loads(body) if body.strip() else {}


def ollama_classify_sale(base_url: str, model: str, page_url: str, plain: str) -> tuple[bool, str]:
    snippet = plain[:MAX_TEXT_OLLAMA]
    if len(plain) > MAX_TEXT_OLLAMA:
        snippet += "\n\n[…truncated…]"
    user = f"Page URL: {page_url}\n\nPage text:\n{snippet}"
    endpoint = base_url.rstrip("/") + "/api/chat"
    payload: dict = {
        "model": model,
        "messages": [
            {"role": "system", "content": OLLAMA_SYSTEM},
            {"role": "user", "content": user},
        ],
        "stream": False,
        "options": {"temperature": 0.1},
        "format": "json",
    }
    data = http_post_json(endpoint, payload, OLLAMA_CHAT_TIMEOUT)
    raw = (data.get("message") or {}).get("content", "")
    if not raw:
        raise RuntimeError("empty Ollama message")
    parsed = _parse_json_object(raw)
    sale = _coerce_bool(parsed.get("sale", False))
    rationale = str(parsed.get("rationale", "")).strip() or "(no rationale)"
    return sale, rationale


def main() -> int:
    ap = argparse.ArgumentParser(description="Sale yes/no scan for README links (heuristic and/or Ollama).")
    ap.add_argument("--readme", type=Path, default=README_DEFAULT)
    ap.add_argument("--out", type=Path, default=OUT_DEFAULT)
    ap.add_argument("--blocklist", type=Path, default=BLOCKLIST_DEFAULT)
    ap.add_argument("--limit", type=int, default=0, metavar="N", help="max successful fetches; 0 = all")
    args = ap.parse_args()

    use_ollama = _truthy_env("USE_OLLAMA")
    ollama_base = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434").strip()
    ollama_model = os.environ.get("OLLAMA_MODEL", "llama3.2").strip()

    if not args.readme.is_file():
        print(f"Missing {args.readme}", file=sys.stderr)
        return 1

    blocklist = load_blocklist(args.blocklist)
    md = args.readme.read_text(encoding="utf-8")
    urls = extract_links(md)

    rows: list[tuple[str, str, str]] = []  # url, Yes|No, notes
    skipped_blocklist = 0
    skipped_fetch = 0
    newly_blocked = 0
    processed = 0
    n_yes = 0
    n_no = 0

    for url in urls:
        if args.limit and processed >= args.limit:
            break

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
            rows.append((url, "—", f"fetch failed ({code}) {err[:60]}"))
            skipped_fetch += 1
            continue

        processed += 1
        plain = html_to_text(body)
        heur_yes, hits = detect_sale(plain)
        heur_hint = ", ".join(hits[:6]) + ("…" if len(hits) > 6 else "") if hits else "—"

        if use_ollama:
            try:
                o_yes, rationale = ollama_classify_sale(ollama_base, ollama_model, url, plain)
                if o_yes:
                    n_yes += 1
                    yn = "**Yes**"
                else:
                    n_no += 1
                    yn = "**No**"
                notes = f"{rationale} _Heuristic: {'Yes' if heur_yes else 'No'} ({heur_hint})._"
                rows.append((url, yn, notes))
            except Exception as e:
                print(f"Ollama failed for {url}: {e}", file=sys.stderr)
                if heur_yes:
                    n_yes += 1
                    rows.append((url, "**Yes**", f"(Ollama error, heuristic) {heur_hint}"))
                else:
                    n_no += 1
                    rows.append((url, "**No**", f"(Ollama error, heuristic) {heur_hint}"))
            time.sleep(OLLAMA_SLEEP_SEC)
        else:
            if heur_yes:
                n_yes += 1
                rows.append((url, "**Yes**", heur_hint))
            else:
                n_no += 1
                rows.append((url, "**No**", "—"))

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    mode = (
        f"**Ollama** `{ollama_model}` @ `{ollama_base}` (heuristic shown for comparison)."
        if use_ollama
        else "**Heuristic keywords** only (no LLM)."
    )
    lines = [
        "# Deal scan",
        "",
        f"Generated **{ts}** from `{args.readme.name}`. {mode}",
        "",
        f"**Summary:** {n_yes} Yes / {n_no} No (among {processed} pages fetched). "
        f"Blocklist skips: {skipped_blocklist}; fetch failures: {skipped_fetch}; new 403→blocklist: {newly_blocked}.",
        "",
        "| URL | Sale detected? | Notes |",
        "|-----|----------------|-------|",
    ]
    for u, yn, hint in rows:
        safe_u = u.replace("|", "%7C")
        safe_h = hint.replace("|", "/")
        lines.append(f"| `{safe_u}` | {yn} | {safe_h} |")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"Yes: {n_yes}  No: {n_no}  (fetched pages: {processed})", file=sys.stderr)
    print(f"Wrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
