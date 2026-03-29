# Deal scan (GitHub Models)

Run from the repo root (requires `GITHUB_TOKEN` with **models read**):

```bash
export GITHUB_TOKEN="$(gh auth token)"
python3 scripts/deal_scan_test.py
```

This file is **overwritten** by that command. Hosts listed in `deal-scan-blocklist.txt` are **not fetched** — they previously returned 403 and are excluded by policy.

| Description | Link |
|-------------|------|
| *Not generated yet — run `scripts/deal_scan_test.py` with `GITHUB_TOKEN`.* | — |
