#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Фильтр MTProto-прокси по geo-стране через ip-api.com.

Скрипт читает `configs/mtproto` (по умолчанию), парсит строки mtproto-прокси и
оставляет/считает только те, у которых countryCode == DOCKER_LOCATION_FILTER.

Важно:
 - Для geo-lookup используется значение `server` из mtproto-строки (IP или hostname).
   ip-api.com принимает и IP, и hostname.
 - Исходный файл не изменяется: выводятся только счётчики (passed / total).
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


sys.path.insert(0, os.getcwd())
try:
    # Рекомендуемый запуск из корня проекта: `python lib/filter_mtproto_by_country.py`
    from lib.mtproto_checker import _load_raw_lines, _parse_mtproto
except ImportError:
    # fallback при запуске не из корня
    from mtproto_checker import _load_raw_lines, _parse_mtproto


class _MinIntervalRateLimiter:
    """Глобальный минимальный интервал между стартами запросов к API."""

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
    ip_or_host: str,
    geo_api_template: str,
    timeout: float,
    max_retries: int,
    retry_base_seconds: float,
) -> str:
    """
    Возвращает countryCode (upper) или пустую строку при ошибке/неуспехе.
    """
    url = geo_api_template.format(ip=ip_or_host)
    for attempt in range(max(1, max_retries)):
        req = Request(url, headers={"User-Agent": "XRayCheck/geo-filter"})
        try:
            with urlopen(req, timeout=timeout) as r:
                raw = r.read().decode("utf-8", errors="replace")
                data = json.loads(raw)
                if str(data.get("status", "")).lower() != "success":
                    return ""
                return (data.get("countryCode") or "").strip().upper()
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
            return ""
        except URLError:
            time.sleep(min(15.0, retry_base_seconds * (2**attempt)))
            continue
        except Exception:
            return ""
    return ""


def _geo_lookup_parallel(
    ip_or_host: str,
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
    # Важно: возвращаемся только если в кэше уже есть НЕпустой countryCode.
    # Иначе мы могли пометить host как missing_hosts, но lookup не выполнится.
    with cache_lock:
        existing = cache.get(ip_or_host, "")
        if (existing or "").strip():
            return

    # Сдвигаем под rate limiter ДО захвата семафора.
    rate.wait_turn()

    sem.acquire()
    try:
        with cache_lock:
            existing = cache.get(ip_or_host, "")
            if (existing or "").strip():
                return
        if jitter_delay > 0:
            time.sleep(jitter_delay)

        cc = _geo_fetch_http(
            ip_or_host=ip_or_host,
            geo_api_template=geo_api_template,
            timeout=timeout,
            max_retries=max_retries,
            retry_base_seconds=retry_base_seconds,
        )

        with cache_lock:
            cache[ip_or_host] = cc
    finally:
        sem.release()


def _fill_geo_cache_parallel(
    missing_hosts: list[str],
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
    if not missing_hosts:
        return

    rate = _MinIntervalRateLimiter(requests_per_minute)
    sem = threading.Semaphore(max(1, int(max_concurrent)))
    cache_lock = threading.Lock()
    workers = min(max(1, int(max_workers)), len(missing_hosts))

    def _one(host: str) -> None:
        _geo_lookup_parallel(
            host,
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
        futures = [ex.submit(_one, host) for host in missing_hosts]
        for fut in as_completed(futures):
            fut.result()


def _load_geo_cache(cache_file: str | None) -> dict[str, str]:
    if not cache_file or not os.path.isfile(cache_file):
        return {}
    try:
        with open(cache_file, "r", encoding="utf-8") as f:
            raw = json.load(f)
        if not isinstance(raw, dict):
            return {}
        out: dict[str, str] = {}
        for k, v in raw.items():
            if not isinstance(k, str):
                continue
            out[str(k)] = str(v).strip().upper()
        return out
    except Exception:
        return {}


def _save_geo_cache(cache_file: str | None, geo_cache: dict[str, str]) -> None:
    if not cache_file:
        return
    parent = os.path.dirname(cache_file)
    if parent:
        os.makedirs(parent, exist_ok=True)
    try:
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(geo_cache, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Filter MTProto configs by geo countryCode using ip-api.com"
    )
    parser.add_argument(
        "input_file",
        nargs="?",
        default=os.path.join("configs", "mtproto"),
        help="Path to mtproto input file (default: configs/mtproto)",
    )
    parser.add_argument(
        "--geo-cache-file",
        default=os.path.join("configs", "geoip_cache_mtproto.json"),
        help="JSON cache file: ip/host -> countryCode",
    )
    parser.add_argument(
        "--geo-api-url",
        default="http://ip-api.com/json/{ip}?fields=countryCode,status,message",
        help="ip-api URL template with {ip}",
    )
    parser.add_argument("--geo-timeout", type=float, default=5.0)
    parser.add_argument("--geo-delay", type=float, default=0.0)
    parser.add_argument(
        "--geo-requests-per-minute",
        type=float,
        default=45.0,
        help="Target global start rate for ip-api (~45/min).",
    )
    parser.add_argument("--geo-max-concurrent", type=int, default=6)
    parser.add_argument("--geo-workers", type=int, default=32)
    parser.add_argument("--geo-max-retries", type=int, default=4)
    parser.add_argument("--geo-retry-base-seconds", type=float, default=2.0)
    parser.add_argument(
        "--allow-incomplete",
        action="store_true",
        help="Allow lines without secret (if present) in mtproto parsing.",
    )
    parser.add_argument(
        "--output-file",
        default="",
        help="If set, write all passed MTProto lines into this file.",
    )
    parser.add_argument(
        "--output-top-file",
        default="",
        help="If set, write up to --top-n passed MTProto lines into this file.",
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=100,
        help="Top-N to write into output-top-file (preserves order).",
    )
    args = parser.parse_args()

    location = (os.environ.get("DOCKER_LOCATION_FILTER") or "").strip().upper() or "RU"
    if not os.environ.get("DOCKER_LOCATION_FILTER"):
        print("::warning::DOCKER_LOCATION_FILTER not set; defaulting to RU", flush=True)
    if len(location) < 2:
        print(f"::error::Invalid DOCKER_LOCATION_FILTER={location!r}", flush=True)
        return 1

    input_path = args.input_file
    if not os.path.isfile(input_path) or os.path.getsize(input_path) == 0:
        print(f"{input_path} missing or empty - nothing to filter.")
        return 0

    raw_lines = _load_raw_lines(input_path)
    parsed_items: list[tuple[str, str]] = []
    for line in raw_lines:
        parsed = _parse_mtproto(line, strict=True, allow_incomplete=bool(args.allow_incomplete))
        if not parsed:
            continue
        host, _port, _normalized, _key = parsed
        parsed_items.append((line, host))

    total_valid = len(parsed_items)
    if total_valid == 0:
        print("No valid MTProto proxies parsed from input.")
        return 0

    unique_hosts = sorted({host for _line, host in parsed_items if host})

    geo_cache = _load_geo_cache(args.geo_cache_file)
    # Backward-compat: если есть старый ru-кэш и новый кэш не заполнен - подтянем его.
    fallback_ru_cache = os.path.join("configs", "geoip_cache_mtproto_ru.json")
    if not geo_cache and args.geo_cache_file != fallback_ru_cache and os.path.isfile(fallback_ru_cache):
        geo_cache = _load_geo_cache(fallback_ru_cache)

    missing_hosts = [
        host
        for host in unique_hosts
        if not (geo_cache.get(host, "") or "").strip()
    ]

    if missing_hosts:
        print(
            f"Geo lookup: missing_hosts={len(missing_hosts)} (unique_hosts={len(unique_hosts)})."
        )
        _fill_geo_cache_parallel(
            missing_hosts,
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
        _save_geo_cache(args.geo_cache_file, geo_cache)

    passed_lines: list[str] = []
    for line, host in parsed_items:
        if (geo_cache.get(host, "") or "") == location:
            passed_lines.append(line)

    passed = len(passed_lines)

    if args.output_file:
        parent = os.path.dirname(args.output_file)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(args.output_file, "w", encoding="utf-8") as f:
            f.write("\n".join(passed_lines) + ("\n" if passed_lines else ""))

    if args.output_top_file:
        parent = os.path.dirname(args.output_top_file)
        if parent:
            os.makedirs(parent, exist_ok=True)
        top_lines = passed_lines[: max(0, int(args.top_n))]
        with open(args.output_top_file, "w", encoding="utf-8") as f:
            f.write("\n".join(top_lines) + ("\n" if top_lines else ""))

    print(
        f"MTProto geo filter: location={location} passed={passed} / total={total_valid} "
        f"(unique_hosts={len(unique_hosts)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

