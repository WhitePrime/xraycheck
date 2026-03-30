#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import ipaddress
import os
import socket
import sys
from bisect import bisect_right
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.getcwd())
from lib.parsing import parse_proxy_url


def _load_ipv4_ranges(cidr_path: str) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Filter configs by real IP location")
    parser.add_argument("input_file")
    parser.add_argument("--location", default="", help="Location code, currently RU supported")
    parser.add_argument("--cidr-file", default="cidrlist")
    parser.add_argument(
        "--fail-open",
        action="store_true",
        help="If filter matches zero, keep original file contents",
    )
    args = parser.parse_args()

    location = (args.location or "").strip().upper()
    path = args.input_file
    cidr_path = args.cidr_file

    if not location:
        print("DOCKER_LOCATION_FILTER empty - location filter disabled.")
        return 0
    if location != "RU":
        print(
            f"::warning::DOCKER_LOCATION_FILTER={location} is not supported by real-IP mode. "
            "Only RU is supported; skipping filter."
        )
        return 0
    if not os.path.isfile(path) or os.path.getsize(path) == 0:
        print(f"{path} missing or empty - location filter skipped.")
        return 0
    if not os.path.isfile(cidr_path) or os.path.getsize(cidr_path) == 0:
        print("::warning::cidrlist missing or empty; real-IP filter skipped.")
        return 0

    merged_ranges = _load_ipv4_ranges(cidr_path)
    if not merged_ranges:
        print("::warning::cidrlist has no valid IPv4 subnets; real-IP filter skipped.")
        return 0
    starts = [s for s, _ in merged_ranges]

    def ip_in_cidr(ip_text: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip_text)
        except ValueError:
            return False
        if ip_obj.version != 4:
            return False
        val = int(ip_obj)
        idx = bisect_right(starts, val) - 1
        return idx >= 0 and val <= merged_ranges[idx][1]

    total = 0
    all_lines: list[str] = []
    links_hosts: list[tuple[str, str]] = []
    unique_hosts: set[str] = set()
    skipped_no_host = 0
    skipped_no_ip = 0

    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n")
            link = _extract_link(line)
            if not link:
                continue
            all_lines.append(line)
            total += 1
            host = _host_from_link(link)
            if not host:
                links_hosts.append((line, ""))
                skipped_no_host += 1
                continue
            links_hosts.append((line, host))
            unique_hosts.add(host)

    host_to_ips: dict[str, list[str]] = {}
    if unique_hosts:
        workers = min(64, len(unique_hosts))
        hosts = sorted(unique_hosts)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            for host, ips in zip(hosts, ex.map(_resolve_ipv4_all, hosts)):
                host_to_ips[host] = ips

    kept: list[str] = []
    for line, host in links_hosts:
        if not host:
            continue
        ips = host_to_ips.get(host, [])
        if not ips:
            skipped_no_ip += 1
            continue
        if any(ip_in_cidr(ip) for ip in ips):
            kept.append(line)

    if kept:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(kept) + "\n")
        print(
            f"Real-IP filter: location={location}, before={total}, after={len(kept)}, "
            f"cidr_ranges={len(merged_ranges)}, unique_hosts={len(unique_hosts)}, "
            f"skipped_no_host={skipped_no_host}, skipped_no_ip={skipped_no_ip}"
        )
        return 0

    if args.fail_open:
        with open(path, "w", encoding="utf-8") as f:
            if all_lines:
                f.write("\n".join(all_lines) + "\n")
        print(
            f"::warning::Real-IP filter (location={location}) matched 0 configs (before={total}); "
            "keeping merged list unchanged."
        )
        return 0

    with open(path, "w", encoding="utf-8") as f:
        pass
    print(f"Real-IP filter: location={location}, before={total}, after=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
