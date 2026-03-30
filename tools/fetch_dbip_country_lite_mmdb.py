#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Скачивает бесплатный db-ip country-lite в формате MMDB (без ключа).
Подходит для geoip2.Reader вместе с --geo-mmdb.

Пример:
  python tools/fetch_dbip_country_lite_mmdb.py configs/dbip-country-lite.mmdb
"""
from __future__ import annotations

import gzip
import os
import sys
import urllib.request
from datetime import datetime, timezone


def main() -> int:
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join("configs", "dbip-country-lite.mmdb")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if not os.path.isabs(out):
        out = os.path.join(root, out)
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)

    now = datetime.now(timezone.utc)
    y, m = now.year, now.month
    for _ in range(36):
        url = f"https://download.db-ip.com/free/dbip-country-lite-{y}-{m:02d}.mmdb.gz"
        data: bytes | None = None
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "xraycheck-fetch/1.0"})
            with urllib.request.urlopen(req, timeout=180) as resp:
                raw = resp.read()
            data = gzip.decompress(raw)
        except Exception:
            pass
        if data is None:
            m -= 1
            if m < 1:
                m = 12
                y -= 1
            continue
        try:
            with open(out, "wb") as f:
                f.write(data)
        except OSError as e:
            print(f"ERROR: cannot write {out}: {e}", file=sys.stderr)
            return 1
        print(f"OK {len(data)} bytes -> {out}", flush=True)
        print(url, flush=True)
        return 0

    print("ERROR: could not download db-ip country-lite (tried last 36 months)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
