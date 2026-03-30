#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Разделяет список конфигов по двум критериям для location (RU):

1) cidr_match: хотя бы один IPv4 endpoint входит в cidrlist (cidr-file).
2) geo_match: countryCode IP endpoint равен location (ip-api.com и/или локальный MMDB).

Флаг --geo-only: cidr-file не читается, cidr_match всегда false (только гео).

Выход:
 - output_geo: строки, у которых geo_match == True (независимо от cidr_match)
 - output_cidr_geo: строки, у которых cidr_match == True И geo_match == True

Требования:
 - сохранить исходные строки целиком (включая комментарий после '#')
 - резолв доменов только в IPv4 (A-записи), как в текущем filter_configs_by_location_ip.py
 - файловый кэш geo lookup, чтобы не упираться в лимиты ip-api.com
 - опционально --geo-mmdb: MaxMind GeoLite2-Country / совместимый MMDB (например db-ip lite) - быстрый офлайн-lookup
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import random
import socket
import sys
import threading
import time
from bisect import bisect_right
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

sys.path.insert(0, os.getcwd())
from lib.parsing import parse_proxy_url
from lib.parsing import normalize_proxy_link


def _extract_link(line: str) -> str:
    s = line.strip()
    if not s:
        return ""
    if "#" in s:
        return s.split("#", 1)[0].strip()
    return s.split(maxsplit=1)[0].strip()


def _host_from_link(link: str) -> str:
    parsed = parse_proxy_url(link)
    if isinstance(parsed, dict):
        h = (parsed.get("address") or "").strip()
        if h:
            return h
    return ""


def _load_ipv4_ranges(cidr_path: str) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    if not cidr_path or not os.path.isfile(cidr_path):
        return []
    with open(cidr_path, "r", encoding="utf-8") as f:
        for raw in f:
            s = raw.strip()
            if not s or s.startswith("#"):
                continue
            try:
                net = ipaddress.ip_network(s, strict=False)
            except ValueError:
                continue
            if net.version != 4:
                continue
            ranges.append((int(net.network_address), int(net.broadcast_address)))
    if not ranges:
        return []
    ranges.sort()
    merged: list[tuple[int, int]] = []
    cur_s, cur_e = ranges[0]
    for s, e in ranges[1:]:
        if s <= cur_e + 1:
            if e > cur_e:
                cur_e = e
        else:
            merged.append((cur_s, cur_e))
            cur_s, cur_e = s, e
    merged.append((cur_s, cur_e))
    return merged


def _resolve_ipv4_all(host: str) -> list[str]:
    if not host:
        return []
    try:
        ip_obj = ipaddress.ip_address(host)
        return [str(ip_obj)] if ip_obj.version == 4 else []
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
    except OSError:
        return []

    ips: set[str] = set()
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        ip = sockaddr[0]
        if ip:
            ips.add(ip)
    return sorted(ips)


class _MinIntervalRateLimiter:
    """Глобальный минимальный интервал между вызовами wait_turn() (старт запросов к API)."""

    def __init__(self, requests_per_minute: float) -> None:
        self._interval = 60.0 / max(1.0, float(requests_per_minute))
        self._lock = threading.Lock()
        self._earliest_next = 0.0

    def wait_turn(self) -> None:
        with self._lock:
            now = time.monotonic()
            wait = max(0.0, self._earliest_next - now)
            self._earliest_next = max(self._earliest_next, now) + self._interval
        if wait > 0:
            time.sleep(wait)


def _parse_retry_after_seconds(exc: HTTPError) -> float | None:
    try:
        ra = exc.headers.get("Retry-After")
        if not ra:
            return None
        return float(ra.strip())
    except (TypeError, ValueError):
        return None


def _geo_fetch_http(
    ip: str,
    geo_api_template: str,
    timeout: float,
    max_retries: int,
    retry_base_seconds: float,
) -> dict[str, Any] | None:
    url = geo_api_template.format(ip=ip)
    for attempt in range(max(1, max_retries)):
        req = Request(url, headers={"User-Agent": "XRayCheck/geo-filter"})
        try:
            with urlopen(req, timeout=timeout) as r:
                raw = r.read().decode("utf-8", errors="replace")
                return json.loads(raw)
        except HTTPError as e:
            if e.code == 429:
                ra = _parse_retry_after_seconds(e)
                backoff = ra if ra is not None else min(60.0, retry_base_seconds * (2**attempt))
                backoff += random.uniform(0, 0.35)
                time.sleep(backoff)
                continue
            if 500 <= e.code < 600:
                time.sleep(min(30.0, retry_base_seconds * (2**attempt)))
                continue
            return None
        except URLError:
            time.sleep(min(15.0, retry_base_seconds * (2**attempt)))
            continue
        except Exception:
            return None
    return None


def _geo_lookup_ip_parallel(
    ip: str,
    cache: dict[str, str],
    cache_lock: threading.Lock,
    rate: _MinIntervalRateLimiter,
    sem: threading.Semaphore,
    geo_api_template: str,
    timeout: float,
    jitter_delay: float,
    max_retries: int,
    retry_base_seconds: float,
) -> None:
    with cache_lock:
        if ip in cache:
            return
    rate.wait_turn()
    sem.acquire()
    try:
        with cache_lock:
            if ip in cache:
                return
        if jitter_delay > 0:
            time.sleep(jitter_delay)
        data = _geo_fetch_http(ip, geo_api_template, timeout, max_retries, retry_base_seconds)
        cc = ""
        if data is not None:
            if str(data.get("status", "")).lower() != "success":
                cc = ""
            else:
                cc = (data.get("countryCode") or "").strip().upper()
        with cache_lock:
            cache[ip] = cc
    finally:
        sem.release()


def _fill_geo_cache_parallel(
    missing_ips: list[str],
    geo_cache: dict[str, str],
    *,
    geo_api_template: str,
    geo_timeout: float,
    geo_delay: float,
    requests_per_minute: float,
    max_concurrent: int,
    max_workers: int,
    max_retries: int,
    retry_base_seconds: float,
) -> None:
    if not missing_ips:
        return
    rate = _MinIntervalRateLimiter(requests_per_minute)
    sem = threading.Semaphore(max(1, int(max_concurrent)))
    cache_lock = threading.Lock()
    workers = min(max(1, int(max_workers)), len(missing_ips))

    def _one(ip: str) -> None:
        _geo_lookup_ip_parallel(
            ip,
            geo_cache,
            cache_lock,
            rate,
            sem,
            geo_api_template,
            geo_timeout,
            geo_delay,
            max_retries,
            retry_base_seconds,
        )

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(_one, ip) for ip in missing_ips]
        for fut in as_completed(futures):
            fut.result()


def _fill_geo_cache_mmdb(missing_ips: list[str], geo_cache: dict[str, str], mmdb_path: str) -> None:
    """Заполняет geo_cache по локальному MMDB (GeoLite2-Country или совместимый db-ip)."""
    try:
        import geoip2.database
        import geoip2.errors
    except ImportError:
        print(
            "::error::geoip2 is required for --geo-mmdb. Install: pip install geoip2",
            file=sys.stderr,
        )
        raise SystemExit(2)

    with geoip2.database.Reader(mmdb_path) as reader:
        for ip in missing_ips:
            try:
                rec = reader.country(ip)
                cc = (rec.country.iso_code or "").strip().upper()
                geo_cache[ip] = cc
            except geoip2.errors.AddressNotFoundError:
                geo_cache[ip] = ""
            except ValueError:
                geo_cache[ip] = ""


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Split configs by CIDR and geo location (ip-api and/or local MMDB) for RU"
    )
    parser.add_argument("input_file")
    parser.add_argument("--location", default="", help="Location code (currently RU supported)")
    parser.add_argument("--cidr-file", default="cidrlist")
    parser.add_argument("--output-geo", required=True, help="Path for configs where geo_match=true")
    parser.add_argument("--output-cidr-geo", required=True, help="Path for configs where cidr_match=true AND geo_match=true")
    parser.add_argument(
        "--output-geo-only",
        default="",
        help="Optional path for geo_only = output_geo - output_cidr_geo (dedup by normalize_proxy_link).",
    )
    parser.add_argument("--geo-cache-file", default="configs/geoip_cache.json", help="JSON cache file: ip -> countryCode")
    parser.add_argument("--geo-api-url", default="http://ip-api.com/json/{ip}?fields=countryCode,status,message")
    parser.add_argument("--geo-timeout", type=float, default=5.0)
    parser.add_argument(
        "--geo-delay",
        type=float,
        default=0.25,
        help="Доп. пауза (с) перед HTTP после rate-limit слота; лёгкий джиттер к лимиту ip-api.",
    )
    parser.add_argument(
        "--geo-requests-per-minute",
        type=float,
        default=42.0,
        help="Целевой глобальный темп стартов запросов к ip-api (бесплатный лимит ~45/мин).",
    )
    parser.add_argument(
        "--geo-max-concurrent",
        type=int,
        default=3,
        help="Максимум одновременных HTTP к ip-api (поверх интервала rpm).",
    )
    parser.add_argument(
        "--geo-workers",
        type=int,
        default=16,
        help="Размер пула потоков для параллельного geo lookup.",
    )
    parser.add_argument("--geo-max-retries", type=int, default=4, help="Попыток на один IP при 429/5xx/сетевых сбоях.")
    parser.add_argument(
        "--geo-retry-base-seconds",
        type=float,
        default=2.0,
        help="База экспоненциального бэкоффа между ретраями (с).",
    )
    parser.add_argument(
        "--fail-open",
        action="store_true",
        help="If both outputs become empty, keep input as output_geo (для предотвращения полного обнуления).",
    )
    parser.add_argument(
        "--geo-only",
        action="store_true",
        help="Только гео по IP (countryCode); cidr-file не читается, cidr_match всегда false (output_cidr_geo пуст).",
    )
    parser.add_argument(
        "--geo-mmdb",
        default=(os.environ.get("GEOIP_MMDB") or "").strip(),
        metavar="PATH",
        help="Локальный Country MMDB (GeoLite2-Country.mmdb или db-ip-country-lite). "
        "Для IP без записи в кэше - lookup без ip-api; при пустом ответе MMDB остаётся ip-api. Переменная окружения: GEOIP_MMDB.",
    )
    args = parser.parse_args()

    location = (args.location or "").strip().upper()
    if not location:
        print("DOCKER_LOCATION_FILTER empty - geo+cidr split disabled.")
        return 0
    if location != "RU":
        print(f"::warning::Location={location} not supported by this script. Skipping split.")
        return 0

    input_path = args.input_file
    if not os.path.isfile(input_path) or os.path.getsize(input_path) == 0:
        print(f"{input_path} missing or empty - nothing to split.")
        return 0

    ranges = [] if args.geo_only else _load_ipv4_ranges(args.cidr_file)
    starts = [s for s, _ in ranges]

    def ip_in_cidr(ip_text: str) -> bool:
        if not ranges:
            return False
        try:
            ip_obj = ipaddress.ip_address(ip_text)
        except ValueError:
            return False
        if ip_obj.version != 4:
            return False
        val = int(ip_obj)
        idx = bisect_right(starts, val) - 1
        return idx >= 0 and val <= ranges[idx][1]

    all_lines: list[str] = []
    links_hosts: list[tuple[str, str]] = []
    unique_hosts: set[str] = set()
    total = 0

    with open(input_path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n")
            link = _extract_link(line)
            if not link:
                continue
            all_lines.append(line)
            total += 1
            host = _host_from_link(link)
            links_hosts.append((line, host))
            if host:
                unique_hosts.add(host)

    host_to_ips: dict[str, list[str]] = {}
    if unique_hosts:
        workers = min(64, max(1, len(unique_hosts)))
        hosts = sorted(unique_hosts)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            for host, ips in zip(hosts, ex.map(_resolve_ipv4_all, hosts)):
                host_to_ips[host] = ips

    unique_ips: set[str] = set()
    for _, host in links_hosts:
        if not host:
            continue
        for ip in host_to_ips.get(host, []):
            unique_ips.add(ip)

    geo_cache_file = args.geo_cache_file
    geo_cache: dict[str, str] = {}
    if geo_cache_file and os.path.isfile(geo_cache_file):
        try:
            with open(geo_cache_file, "r", encoding="utf-8") as f:
                raw = json.load(f)
                if isinstance(raw, dict):
                    geo_cache = {str(k): str(v).strip().upper() for k, v in raw.items() if isinstance(k, str)}
        except Exception:
            geo_cache = {}

    def _ip_needs_geo_lookup(ip: str) -> bool:
        if ip not in geo_cache:
            return True
        return not (str(geo_cache.get(ip, "") or "").strip())

    missing_ips = [ip for ip in sorted(unique_ips) if _ip_needs_geo_lookup(ip)]
    if missing_ips:
        cached_before = len(unique_ips) - len(missing_ips)
        mmdb_path = (args.geo_mmdb or "").strip()
        if mmdb_path:
            if os.path.isfile(mmdb_path):
                print(
                    f"Geo lookup: {len(missing_ips)} IPs via MMDB (cached JSON: {cached_before}), file={mmdb_path}"
                )
                _fill_geo_cache_mmdb(missing_ips, geo_cache, mmdb_path)
            else:
                print(
                    f"::warning::--geo-mmdb file missing: {mmdb_path}, falling back to ip-api HTTP",
                    flush=True,
                )

    missing_ips = [ip for ip in sorted(unique_ips) if _ip_needs_geo_lookup(ip)]
    if missing_ips:
        cached_before = len(unique_ips) - len(missing_ips)
        print(
            f"Geo lookup: {len(missing_ips)} IPs to fetch (already in cache: {cached_before}), "
            f"rpm={args.geo_requests_per_minute}, concurrent={args.geo_max_concurrent}, "
            f"workers={args.geo_workers}, jitter_delay={args.geo_delay}"
        )
        _fill_geo_cache_parallel(
            missing_ips,
            geo_cache,
            geo_api_template=args.geo_api_url,
            geo_timeout=args.geo_timeout,
            geo_delay=args.geo_delay,
            requests_per_minute=args.geo_requests_per_minute,
            max_concurrent=args.geo_max_concurrent,
            max_workers=args.geo_workers,
            max_retries=args.geo_max_retries,
            retry_base_seconds=args.geo_retry_base_seconds,
        )

    if geo_cache_file:
        os.makedirs(os.path.dirname(geo_cache_file) or ".", exist_ok=True)
        try:
            with open(geo_cache_file, "w", encoding="utf-8") as f:
                json.dump(geo_cache, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    kept_geo: list[str] = []
    kept_cidr_geo: list[str] = []
    skipped_no_host = 0
    skipped_no_ip = 0

    geo_count = 0
    cidr_geo_count = 0

    for line, host in links_hosts:
        if not host:
            skipped_no_host += 1
            continue
        ips = host_to_ips.get(host, [])
        if not ips:
            skipped_no_ip += 1
            continue

        cidr_match = any(ip_in_cidr(ip) for ip in ips)
        geo_match = any((geo_cache.get(ip, "") or "") == location for ip in ips)

        if geo_match:
            kept_geo.append(line)
            geo_count += 1
            if cidr_match:
                kept_cidr_geo.append(line)
                cidr_geo_count += 1

    if args.fail_open and geo_count == 0 and cidr_geo_count == 0 and all_lines:
        kept_geo = list(all_lines)

    os.makedirs(os.path.dirname(args.output_geo) or ".", exist_ok=True)
    os.makedirs(os.path.dirname(args.output_cidr_geo) or ".", exist_ok=True)

    with open(args.output_geo, "w", encoding="utf-8") as f:
        f.write("\n".join(kept_geo) + ("\n" if kept_geo else ""))
    with open(args.output_cidr_geo, "w", encoding="utf-8") as f:
        f.write("\n".join(kept_cidr_geo) + ("\n" if kept_cidr_geo else ""))

    if args.output_geo_only:
        cidr_norm: set[str] = set()

        def _link_from_line(line: str) -> str:
            s = line.strip().split(maxsplit=1)[0].strip()
            return s.split("#", 1)[0].strip() if "#" in s else s

        for l in kept_cidr_geo:
            link = _link_from_line(l)
            n = normalize_proxy_link(link)
            if n:
                cidr_norm.add(n)

        geo_only: list[str] = []
        for l in kept_geo:
            link = _link_from_line(l)
            n = normalize_proxy_link(link)
            if n and n not in cidr_norm:
                geo_only.append(l)

        os.makedirs(os.path.dirname(args.output_geo_only) or ".", exist_ok=True)
        with open(args.output_geo_only, "w", encoding="utf-8") as f:
            f.write("\n".join(geo_only) + ("\n" if geo_only else ""))

    mode = "geo-only (no cidrlist)" if args.geo_only else "geo+cidr"
    print(
        f"Split by {mode}: location={location}, total={total}, "
        f"geo_pass={geo_count}, cidr_geo_pass={cidr_geo_count}, "
        f"unique_hosts={len(unique_hosts)}, unique_ips={len(unique_ips)}, "
        f"skipped_no_host={skipped_no_host}, skipped_no_ip={skipped_no_ip}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

