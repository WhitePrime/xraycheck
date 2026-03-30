#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Бенчмарк: merge по файлу ссылок (как links.txt) + filter_configs_by_cidr_and_geo --geo-only (RU, без cidr).

Пример:
  python -u tools/benchmark_ru_geo_filter.py linksnew\\ copy.txt
  python -u tools/benchmark_ru_geo_filter.py --input-only configs/_debug_ru_geo_input.txt

Пишет сводку в configs/_ru_geo_benchmark_report.txt и в stdout.
"""
from __future__ import annotations

import argparse
import math
import os
import subprocess
import sys
import time


def _count_proxy_lines(path: str) -> int:
    if not os.path.isfile(path) or os.path.getsize(path) == 0:
        return 0
    with open(path, encoding="utf-8") as f:
        return sum(1 for ln in f if ln.strip() and not ln.strip().startswith("#"))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "links_file",
        nargs="?",
        default="",
        help="Файл с URL источников (построчно), как для Daily check",
    )
    ap.add_argument(
        "--input-only",
        default="",
        metavar="PATH",
        help="Пропустить загрузку; взять готовый список конфигов",
    )
    ap.add_argument("--input-out", default="configs/_debug_ru_geo_input.txt")
    ap.add_argument("--output-geo", default="configs/_debug_ru_geo_output.txt")
    ap.add_argument("--geo-cache-file", default="configs/_bench_ru_geo_cache.json")
    ap.add_argument("--geo-requests-per-minute", type=float, default=42.0)
    ap.add_argument("--geo-delay", type=float, default=0.35)
    ap.add_argument("--report", default="configs/_ru_geo_benchmark_report.txt")
    ap.add_argument(
        "--sample-fraction",
        type=float,
        default=1.0,
        help="Доля строк входного списка конфигов (0<..1], например 0.25 для четверти).",
    )
    ap.add_argument(
        "--geo-mmdb",
        default="",
        metavar="PATH",
        help="Путь к Country MMDB; передаётся в filter как --geo-mmdb (без ip-api для новых IP).",
    )
    args = ap.parse_args()

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(root)
    sys.path.insert(0, root)

    lines: list[str] = []

    if args.input_only:
        inp = args.input_only
        if not os.path.isfile(inp):
            print(f"ERROR: --input-only file missing: {inp}", flush=True)
            return 1
        t_fetch = 0.0
        n_in = _count_proxy_lines(inp)
    else:
        if not args.links_file or not os.path.isfile(args.links_file):
            print("ERROR: укажите существующий links_file или --input-only", flush=True)
            return 1
        from lib.parsing import load_merged_keys

        t0 = time.perf_counter()
        _, keys = load_merged_keys(args.links_file)
        t_fetch = time.perf_counter() - t0
        os.makedirs(os.path.dirname(args.input_out) or ".", exist_ok=True)
        with open(args.input_out, "w", encoding="utf-8") as f:
            for link, full in keys:
                line = full if full.endswith("\n") else full + "\n"
                f.write(line)
        inp = args.input_out
        n_in = len(keys)

    sample_tmp = ""
    frac = float(args.sample_fraction)
    if frac < 1.0 - 1e-12:
        if frac <= 0 or frac > 1.0:
            print("ERROR: --sample-fraction must be in (0, 1]", flush=True)
            return 1
        with open(inp, encoding="utf-8") as f:
            lines = [ln for ln in f if ln.strip() and not ln.strip().startswith("#")]
        n_all = len(lines)
        k = max(1, math.ceil(n_all * frac)) if n_all else 0
        sub = lines[:k]
        sample_tmp = os.path.join("configs", ".benchmark_ru_geo_sample.tmp")
        os.makedirs("configs", exist_ok=True)
        with open(sample_tmp, "w", encoding="utf-8") as f:
            for ln in sub:
                f.write(ln if ln.endswith("\n") else ln + "\n")
        inp = sample_tmp
        n_in = len(sub)
        print(f"sample_fraction={frac} lines={n_in}/{n_all}", flush=True)

    out_cidr = os.path.join("configs", ".benchmark_ru_cidr_geo.tmp")
    os.makedirs("configs", exist_ok=True)

    print("=== merge (fetch + parse) ===", flush=True)
    print("time_sec", round(t_fetch, 2), flush=True)
    print("configs_input_unique_links", n_in, flush=True)

    t1 = time.perf_counter()
    cmd: list[str] = [
        sys.executable,
        "-m",
        "lib.filter_configs_by_cidr_and_geo",
        inp,
        "--location",
        "RU",
        "--geo-only",
        "--output-geo",
        args.output_geo,
        "--output-cidr-geo",
        out_cidr,
        "--geo-cache-file",
        args.geo_cache_file,
        "--geo-delay",
        str(args.geo_delay),
        "--geo-requests-per-minute",
        str(args.geo_requests_per_minute),
        "--geo-max-concurrent",
        "3",
        "--geo-workers",
        "16",
    ]
    mmdb = (args.geo_mmdb or "").strip()
    if mmdb:
        if not os.path.isabs(mmdb):
            mmdb = os.path.join(root, mmdb)
        cmd.extend(["--geo-mmdb", mmdb])
    r = subprocess.run(cmd, check=False)
    t_filter = time.perf_counter() - t1
    n_out = _count_proxy_lines(args.output_geo)

    try:
        os.remove(out_cidr)
    except OSError:
        pass
    if sample_tmp:
        try:
            os.remove(sample_tmp)
        except OSError:
            pass

    print("=== geo RU filter (--geo-only, no cidr) ===", flush=True)
    print("exit_code", r.returncode, flush=True)
    print("time_sec", round(t_filter, 2), flush=True)
    print("configs_after_geo_ru", n_out, flush=True)
    print("total_wall_sec", round(t_fetch + t_filter, 2), flush=True)

    note = (
        "Гео-отбор countryCode=RU, без cidrlist. "
        "С --geo-mmdb используется локальный MMDB вместо ip-api для отсутствующих в JSON IP. "
        "Проверки vless_checker/hysteria_checker здесь не запускались."
    )
    rep = os.path.join(root, args.report)
    os.makedirs(os.path.dirname(rep) or ".", exist_ok=True)
    with open(rep, "w", encoding="utf-8") as f:
        f.write(f"configs_input: {n_in}\n")
        f.write(f"configs_after_geo_ru: {n_out}\n")
        f.write(f"time_fetch_sec: {t_fetch:.2f}\n")
        f.write(f"time_geo_filter_sec: {t_filter:.2f}\n")
        f.write(f"time_total_sec: {t_fetch + t_filter:.2f}\n")
        f.write(f"filter_exit_code: {r.returncode}\n")
        f.write(f"geo_rpm: {args.geo_requests_per_minute}\n")
        f.write(f"sample_fraction: {args.sample_fraction}\n")
        f.write(f"geo_mmdb: {mmdb or '(none)'}\n")
        f.write(f"note: {note}\n")
    print(f"Report: {rep}", flush=True)
    return 0 if r.returncode == 0 else r.returncode


if __name__ == "__main__":
    raise SystemExit(main())
