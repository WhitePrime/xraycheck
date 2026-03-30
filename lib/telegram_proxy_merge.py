#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Объединение результатов mtproto_checker и tg_socks_checker в одни файлы (full + top100).

Полный список: все строки MTProto (в порядке скора чекера), затем все SOCKS.
Топ: round-robin по двум top100, чтобы оба типа попадали в выборку.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from urllib.parse import unquote

try:
    from .mtproto_checker import _append_channel_to_proxy_url, _parse_mtproto
    from .tg_socks_checker import _append_channel_to_socks_url, _parse_tg_socks
except ImportError:
    from mtproto_checker import _append_channel_to_proxy_url, _parse_mtproto
    from tg_socks_checker import _append_channel_to_socks_url, _parse_tg_socks


def read_nonempty_lines(path: Path) -> list[str]:
    if not path.is_file() or path.stat().st_size == 0:
        return []
    out: list[str] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = raw.strip()
        if s and not s.startswith("#"):
            out.append(s)
    return out


def split_combined_telegram_proxies(lines: list[str]) -> tuple[list[str], list[str]]:
    mt: list[str] = []
    sk: list[str] = []
    for s in lines:
        if _parse_tg_socks(s):
            sk.append(s)
        elif _parse_mtproto(s, strict=True, allow_incomplete=False):
            mt.append(s)
    return mt, sk


def split_combined_file_to_staging(inp: Path, out_mt: Path, out_sk: Path) -> tuple[int, int]:
    text = inp.read_text(encoding="utf-8", errors="replace") if inp.is_file() and inp.stat().st_size > 0 else ""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    mt, sk = split_combined_telegram_proxies(lines)
    out_mt.parent.mkdir(parents=True, exist_ok=True)
    out_sk.parent.mkdir(parents=True, exist_ok=True)
    out_mt.write_text("\n".join(mt) + ("\n" if mt else ""), encoding="utf-8")
    out_sk.write_text("\n".join(sk) + ("\n" if sk else ""), encoding="utf-8")
    return len(mt), len(sk)


def merge_round_robin_top(mt_top: list[str], sk_top: list[str], top_n: int) -> list[str]:
    out: list[str] = []
    i, j = 0, 0
    n = max(1, top_n)
    while len(out) < n and (i < len(mt_top) or j < len(sk_top)):
        if i < len(mt_top):
            out.append(mt_top[i])
            i += 1
        if len(out) >= n:
            break
        if j < len(sk_top):
            out.append(sk_top[j])
            j += 1
    return out


def resolve_side(
    for_check_path: Path,
    st_full: Path,
    st_top: Path,
    from_prev_mt: list[str],
    from_prev_sk: list[str],
    *,
    socks: bool,
    top_n: int,
) -> tuple[list[str], list[str]]:
    """
    Если for_check непустой - берём результат чекера из staging; иначе - соответствующий список из разбивки prev.
    """
    if for_check_path.is_file() and for_check_path.stat().st_size > 0:
        full = read_nonempty_lines(st_full)
        top = read_nonempty_lines(st_top)
        return full, top
    prev_side = list(from_prev_sk if socks else from_prev_mt)
    tn = max(1, top_n)
    return prev_side, prev_side[:tn]


def apply_channel_tag_line(line: str, channel: str) -> str:
    """Тег канала для строки MTProto (tg://proxy, t.me/proxy) или SOCKS (t.me/socks, tg://socks)."""
    raw = line.rstrip("\n")
    s = raw.strip()
    if not s or s.startswith("#"):
        return raw
    ch = unquote(channel.strip())
    if _parse_tg_socks(s):
        return _append_channel_to_socks_url(raw.strip(), ch)
    if _parse_mtproto(s, strict=True, allow_incomplete=False):
        return _append_channel_to_proxy_url(raw.strip(), ch)
    return raw


def rewrite_file_channel_tags(path: Path, channel: str) -> None:
    if not path.is_file() or path.stat().st_size == 0:
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    out = [apply_channel_tag_line(line, channel) for line in lines]
    path.write_text("\n".join(out) + ("\n" if out else ""), encoding="utf-8")


def merge_staging_only(
    *,
    st_mt: Path,
    st_mt100: Path,
    st_sk: Path,
    st_sk100: Path,
    out_full: Path,
    out_top: Path,
    top_n: int,
) -> None:
    """Слияние только из staging-файлов чекеров (Docker после раздельного прогона)."""
    mt_full = read_nonempty_lines(st_mt)
    sk_full = read_nonempty_lines(st_sk)
    mt_top = read_nonempty_lines(st_mt100)
    sk_top = read_nonempty_lines(st_sk100)
    tn = max(1, top_n)
    if not mt_top and mt_full:
        mt_top = mt_full[:tn]
    if not sk_top and sk_full:
        sk_top = sk_full[:tn]
    combined_full = mt_full + sk_full
    combined_top = merge_round_robin_top(mt_top, sk_top, tn)
    out_full.parent.mkdir(parents=True, exist_ok=True)
    out_full.write_text("\n".join(combined_full) + ("\n" if combined_full else ""), encoding="utf-8")
    out_top.write_text("\n".join(combined_top) + ("\n" if combined_top else ""), encoding="utf-8")


def merge_from_workflow(
    *,
    prev_path: Path,
    for_mt: Path,
    for_sk: Path,
    st_mt: Path,
    st_mt100: Path,
    st_sk: Path,
    st_sk100: Path,
    out_full: Path,
    out_top: Path,
    top_n: int,
) -> None:
    prev_lines = read_nonempty_lines(prev_path)
    prev_mt, prev_sk = split_combined_telegram_proxies(prev_lines)

    try:
        top_n_i = int(top_n)
    except (TypeError, ValueError):
        top_n_i = 100
    tn = max(1, top_n_i)

    mt_full, mt_top = resolve_side(
        for_mt, st_mt, st_mt100, prev_mt, prev_sk, socks=False, top_n=tn
    )
    sk_full, sk_top = resolve_side(
        for_sk, st_sk, st_sk100, prev_mt, prev_sk, socks=True, top_n=tn
    )

    if not mt_top and mt_full:
        mt_top = mt_full[:tn]
    if not sk_top and sk_full:
        sk_top = sk_full[:tn]

    combined_full = mt_full + sk_full
    combined_top = merge_round_robin_top(mt_top, sk_top, tn)

    out_full.parent.mkdir(parents=True, exist_ok=True)
    out_full.write_text("\n".join(combined_full) + ("\n" if combined_full else ""), encoding="utf-8")
    out_top.write_text("\n".join(combined_top) + ("\n" if combined_top else ""), encoding="utf-8")


def main() -> None:
    p = argparse.ArgumentParser(description="Слияние выходов MTProto + Telegram SOCKS в один список.")
    p.add_argument("--prev", type=Path, default=Path("mtproto_prev.txt"))
    p.add_argument("--for-mt", type=Path, default=Path("mtproto_for_check.txt"))
    p.add_argument("--for-sk", type=Path, default=Path("tg_socks_for_check.txt"))
    p.add_argument("--st-mt", type=Path, default=Path("configs/_st_mtproto"))
    p.add_argument("--st-mt100", type=Path, default=Path("configs/_st_mtproto(top100)"))
    p.add_argument("--st-sk", type=Path, default=Path("configs/_st_tg_socks"))
    p.add_argument("--st-sk100", type=Path, default=Path("configs/_st_tg_socks(top100)"))
    p.add_argument("--out", type=Path, default=Path("configs/mtproto"))
    p.add_argument("--out-top", type=Path, default=Path("configs/mtproto(top100)"))
    p.add_argument("--top-n", type=int, default=100)
    ns = p.parse_args()
    try:
        tni = int(ns.top_n)
    except (TypeError, ValueError):
        tni = 100
    merge_from_workflow(
        prev_path=ns.prev,
        for_mt=ns.for_mt,
        for_sk=ns.for_sk,
        st_mt=ns.st_mt,
        st_mt100=ns.st_mt100,
        st_sk=ns.st_sk,
        st_sk100=ns.st_sk100,
        out_full=ns.out,
        out_top=ns.out_top,
        top_n=tni,
    )


if __name__ == "__main__":
    main()
