#!/usr/bin/env python3
"""Mirror files under configs/ to configs/base64/<same name> (entire file as one base64 string)."""
from __future__ import annotations

import argparse
import base64
from pathlib import Path


def encode_file(src: Path, out_root: Path) -> None:
    out_root.mkdir(parents=True, exist_ok=True)
    dest = out_root / src.name
    raw = src.read_bytes()
    b64 = base64.b64encode(raw).decode("ascii")
    dest.write_text(b64 + ("\n" if b64 else ""), encoding="ascii")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Write whole-file base64 to configs/base64/<basename> for each input file."
    )
    ap.add_argument(
        "paths",
        nargs="*",
        help="Paths (e.g. configs/available). Missing files are skipped.",
    )
    ap.add_argument(
        "--out-dir",
        default="configs/base64",
        help="Output directory (default: configs/base64)",
    )
    args = ap.parse_args()
    out_root = Path(args.out_dir)
    for rel in args.paths:
        src = Path(rel)
        if not src.is_file():
            continue
        encode_file(src, out_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
