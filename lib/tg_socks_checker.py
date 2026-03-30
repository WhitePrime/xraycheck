#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Проверка SOCKS5-прокси из ссылок Telegram вида:
  https://t.me/socks?server=HOST&port=PORT&user=USER&pass=PASS
  tg://socks?server=HOST&port=PORT&user=USER&pass=PASS

Метрика (latency / success rate / jitter) совместима по смыслу с mtproto_checker.py,
но протокол и парсер отдельные - MTProto-логика не меняется.
"""

from __future__ import annotations

import argparse
import os
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, unquote, urlencode, urlparse, urlunparse

import requests
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from lib.config import CONNECT_TIMEOUT, MAX_WORKERS, MODE, OUTPUT_DIR

try:
    from .mtproto_checker import _normalize_host, _normalize_port
except ImportError:
    from mtproto_checker import _normalize_host, _normalize_port

console = Console()

# В итоговой ссылке Telegram ожидает channel=@handle, а не channel=%40handle.
_CHANNEL_PARAM_AT_RE = re.compile(r"(^|&)channel=%40")


def socks_query_force_literal_at_for_channel(query: str) -> str:
    if not query or "channel=%40" not in query:
        return query
    return _CHANNEL_PARAM_AT_RE.sub(r"\1channel=@", query)


_LATENCY_PREFIX_RE = re.compile(r"^\[\d+ms\]\s*", re.MULTILINE)
_ZERO_WIDTH = ("\u200b", "\u200c", "\u200d", "\ufeff")

# Цель CONNECT через прокси (публичный IPv4 + порт)
_SOCKS5_TEST_IPV4 = bytes([1, 1, 1, 1])
_SOCKS5_TEST_PORT = 443


def _env_int(key: str, default: int) -> int:
    v = os.environ.get(key, "").strip()
    if not v:
        return default
    try:
        return int(v)
    except ValueError:
        return default


def _env_float(key: str, default: float) -> float:
    v = os.environ.get(key, "").strip()
    if not v:
        return default
    try:
        return float(v)
    except ValueError:
        return default


def _env_bool(key: str, default: bool) -> bool:
    v = os.environ.get(key, "").strip().lower()
    if not v:
        return default
    return v in ("1", "true", "yes", "on")


def _strip_latency_prefix(line: str) -> str:
    return _LATENCY_PREFIX_RE.sub("", line).strip()


def _normalize_raw_lines(lines: list[str]) -> list[str]:
    out: list[str] = []
    for raw in lines:
        line = _strip_latency_prefix(raw).strip()
        for zw in _ZERO_WIDTH:
            line = line.replace(zw, "")
        if not line or line.startswith("#"):
            continue
        low = line.lower()
        if "tg://socks?" in low:
            line = line[low.find("tg://socks?") :].strip()
        else:
            for needle in (
                "https://t.me/socks?",
                "http://t.me/socks?",
                "https://telegram.me/socks?",
                "http://telegram.me/socks?",
            ):
                if needle in low:
                    line = line[low.find(needle) :].strip()
                    break
        out.append(line)
    return out


def _load_raw_lines(path: str) -> list[str]:
    with open(path, encoding="utf-8") as f:
        return _normalize_raw_lines(f.readlines())


def _load_raw_lines_from_text(text: str) -> list[str]:
    return _normalize_raw_lines(text.splitlines())


def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return bytes(buf)


def _socks5_handshake_and_connect(
    sock: socket.socket,
    username: str,
    password: str,
    timeout: float,
) -> bool:
    sock.settimeout(timeout)
    user = (username or "").encode("utf-8")
    pwd = (password or "").encode("utf-8")
    if len(user) > 255 or len(pwd) > 255:
        return False

    if user or pwd:
        sock.sendall(bytes([0x05, 0x01, 0x02]))
    else:
        sock.sendall(bytes([0x05, 0x01, 0x00]))

    sel = _recv_exact(sock, 2)
    if not sel or sel[0] != 0x05:
        return False
    method = sel[1]
    if method == 0x02:
        if not user and not pwd:
            return False
        auth = bytes([0x01, len(user)]) + user + bytes([len(pwd)]) + pwd
        sock.sendall(auth)
        aresp = _recv_exact(sock, 2)
        if not aresp or aresp[0] != 0x01 or aresp[1] != 0x00:
            return False
    elif method != 0x00:
        return False

    req = bytes([0x05, 0x01, 0x00, 0x01]) + _SOCKS5_TEST_IPV4 + _SOCKS5_TEST_PORT.to_bytes(2, "big")
    sock.sendall(req)
    head = _recv_exact(sock, 4)
    if not head or head[0] != 0x05 or head[1] != 0x00:
        return False
    atyp = head[3]
    if atyp == 0x01:
        return _recv_exact(sock, 6) is not None
    if atyp == 0x03:
        ln_b = _recv_exact(sock, 1)
        if not ln_b:
            return False
        return _recv_exact(sock, ln_b[0] + 2) is not None
    if atyp == 0x04:
        return _recv_exact(sock, 18) is not None
    return False


def _socks5_probe(host: str, port: int, username: str, password: str, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            return _socks5_handshake_and_connect(sock, username, password, timeout)
    except (OSError, socket.error):
        return False


def _parse_tg_socks(line: str) -> Optional[tuple[str, int, str, str, str, tuple[str, int, str, str]]]:
    """
    Возвращает (host, port, user, pass, normalized_url, dedup_key) или None.
    normalized_url - https://t.me/socks?... (канонический вид для вывода).
    """
    s = line.strip()
    if not s:
        return None

    if not (
        s.startswith("tg://")
        or s.startswith("http://")
        or s.startswith("https://")
    ):
        return None

    parsed = urlparse(s)
    if parsed.scheme == "tg":
        if parsed.netloc != "socks":
            return None
    elif parsed.scheme in ("http", "https"):
        if (parsed.netloc or "").lower() not in ("t.me", "telegram.me"):
            return None
        path = (parsed.path or "").rstrip("/")
        if path != "/socks":
            return None
    else:
        return None

    qs = parse_qs(parsed.query)
    server = qs.get("server", [None])[0]
    port_str = qs.get("port", [None])[0]
    user = (qs.get("user", [""])[0] or "").strip()
    pwd = (qs.get("pass", [""])[0] or "").strip()

    if not server or not port_str:
        return None
    try:
        port = int(port_str)
    except ValueError:
        return None

    host_n = _normalize_host(server)
    port_n = _normalize_port(port)
    if host_n is None or port_n is None:
        return None

    q = [("server", host_n), ("port", str(port_n)), ("user", user), ("pass", pwd)]
    query = urlencode(q)
    normalized = f"https://t.me/socks?{query}"
    key = (host_n, port_n, user, pwd)
    return host_n, port_n, user, pwd, normalized, key


def _append_channel_to_socks_url(line: str, channel: str) -> str:
    s = line.strip()
    if not s or s.startswith("#"):
        return line
    try:
        p = urlparse(s)
    except Exception:
        return line
    if p.scheme == "tg":
        if p.netloc != "socks":
            return line
    elif p.scheme in ("http", "https"):
        if (p.netloc or "").lower() not in ("t.me", "telegram.me"):
            return line
        if (p.path or "").rstrip("/") != "/socks":
            return line
    else:
        return line
    qs = parse_qs(p.query or "", keep_blank_values=True)
    qs.pop("channel", None)
    base_query = urlencode(qs, doseq=True)
    ch = unquote((channel or "").strip())
    new_query = (base_query + f"&channel={ch}") if base_query else f"channel={ch}"
    new_query = socks_query_force_literal_at_for_channel(new_query)
    return urlunparse(p._replace(query=new_query))


def _check_proxy(
    host: str,
    port: int,
    username: str,
    password: str,
    timeout: float,
    attempts: int,
    min_success_rate: float,
    jitter_scale_ms: float,
) -> Optional[float]:
    total_attempts = max(1, attempts)
    latencies: list[float] = []

    for _ in range(total_attempts):
        try:
            start = time.perf_counter()
            ok = _socks5_probe(host, port, username, password, timeout)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            if ok:
                latencies.append(elapsed_ms)
        except Exception:
            continue

    if not latencies:
        return None

    success_count = len(latencies)
    fail_count = total_attempts - success_count
    success_rate = success_count / total_attempts

    if success_rate < min_success_rate:
        return None

    avg_latency = sum(latencies) / success_count
    if len(latencies) > 1:
        jitter = max(latencies) - min(latencies)
    else:
        jitter = 0.0

    jitter_factor = 1.0 + (jitter / jitter_scale_ms) if jitter_scale_ms > 0 else 1.0
    fail_penalty = 1.0 + (fail_count / total_attempts) if fail_count > 0 else 1.0
    return avg_latency * jitter_factor * fail_penalty


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="tg_socks_checker.py",
        description="Проверка SOCKS5 (Telegram t.me/socks) по рукопожатию и CONNECT.",
    )
    parser.add_argument("source", help="Локальный файл или URL со списком ссылок")
    parser.add_argument("--workers", type=int, default=MAX_WORKERS, help=f"Потоков (default {MAX_WORKERS})")
    parser.add_argument(
        "--timeout",
        type=float,
        default=float(CONNECT_TIMEOUT),
        help=f"Таймаут на попытку, сек (default {CONNECT_TIMEOUT})",
    )
    parser.add_argument(
        "--attempts",
        type=int,
        default=_env_int("TG_SOCKS_ATTEMPTS", _env_int("MTPROTO_ATTEMPTS", 3)),
        help="Попыток на прокси (env TG_SOCKS_ATTEMPTS / MTPROTO_ATTEMPTS)",
    )
    parser.add_argument(
        "--min-success-rate",
        type=float,
        default=_env_float("TG_SOCKS_MIN_SUCCESS_RATE", _env_float("MTPROTO_MIN_SUCCESS_RATE", 0.67)),
        help="Мин. доля успешных попыток 0..1",
    )
    parser.add_argument(
        "--jitter-scale-ms",
        type=float,
        default=_env_float("TG_SOCKS_JITTER_SCALE_MS", _env_float("MTPROTO_JITTER_SCALE_MS", 300.0)),
        help="Шкала штрафа джиттера, мс",
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=_env_int("TG_SOCKS_TOP_N", _env_int("MTPROTO_TOP_N", 100)),
        help="Размер топа",
    )
    parser.add_argument(
        "--max-candidates",
        type=int,
        default=_env_int("TG_SOCKS_MAX_CANDIDATES", _env_int("MTPROTO_MAX_CANDIDATES", 0)),
        help="Лимит кандидатов (0 = без лимита)",
    )

    ns = parser.parse_args()
    source = ns.source

    if source.startswith(("http://", "https://")):
        try:
            resp = requests.get(source, timeout=30)
        except requests.RequestException as e:
            console.print(f"[red]Ошибка загрузки списка:[/red] {e}")
            sys.exit(1)
        if resp.status_code != 200:
            console.print(f"[red]HTTP {resp.status_code} для {source}[/red]")
            sys.exit(1)
        lines = _load_raw_lines_from_text(resp.text)
    else:
        if not os.path.isfile(source):
            console.print(f"[red]Файл не найден: {source}[/red]")
            sys.exit(1)
        lines = _load_raw_lines(source)

    if not lines:
        console.print("[yellow]Нет строк в источнике.[/yellow]")
        sys.exit(0)

    if MODE == "merge":
        seen: set[str] = set()
        deduped: list[str] = []
        for line in lines:
            if line in seen:
                continue
            seen.add(line)
            deduped.append(line)
        lines = deduped

    parsed: list[tuple[str, int, str, str, str]] = []
    seen_keys: set[tuple[str, int, str, str]] = set()
    for line in lines:
        row = _parse_tg_socks(line)
        if row is None:
            continue
        host, port, user, pwd, normalized, key = row
        if key in seen_keys:
            continue
        seen_keys.add(key)
        parsed.append((host, port, user, pwd, normalized))

    if ns.max_candidates and ns.max_candidates > 0:
        parsed = parsed[: ns.max_candidates]

    if not parsed:
        console.print("[yellow]Не распознано ни одной t.me/socks ссылки.[/yellow]")
        sys.exit(0)

    workers = min(max(1, int(ns.workers)), len(parsed))
    timeout = max(0.5, float(ns.timeout))
    attempts = max(1, int(ns.attempts))
    min_success_rate = max(0.0, min(1.0, float(ns.min_success_rate)))
    jitter_scale_ms = max(0.0, float(ns.jitter_scale_ms))

    console.print(
        f"[cyan]Проверка Telegram SOCKS:[/cyan] {len(parsed)} прокси, timeout={timeout:.1f}s, "
        f"workers={workers}, attempts={attempts}"
    )

    results: list[tuple[str, float]] = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("({task.completed}/{task.total})"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]SOCKS5...[/cyan]", total=len(parsed))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {
                ex.submit(
                    _check_proxy,
                    h,
                    p,
                    u,
                    pw,
                    timeout,
                    attempts,
                    min_success_rate,
                    jitter_scale_ms,
                ): norm
                for h, p, u, pw, norm in parsed
            }
            for fut in as_completed(futures):
                progress.advance(task)
                norm = futures[fut]
                try:
                    score = fut.result()
                except Exception:
                    score = None
                if score is not None:
                    results.append((norm, score))

    output_dir = OUTPUT_DIR or "configs"
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    base = os.environ.get("TG_SOCKS_OUTPUT_BASENAME", "").strip() or "tg_socks"
    out_path = os.path.join(output_dir, base)
    top_path = os.path.join(output_dir, base + "(top100)")

    if not results:
        console.print("[yellow]Нет доступных SOCKS-прокси.[/yellow]")
        Path(out_path).write_text("", encoding="utf-8")
        Path(top_path).write_text("", encoding="utf-8")
        sys.exit(0)

    results.sort(key=lambda x: x[1])

    formatted = [ln for ln, _ in results]
    ch = os.environ.get("TG_SOCKS_CHANNEL_TAG", "").strip() or os.environ.get("MTPROTO_CHANNEL_TAG", "").strip()
    if ch:
        formatted = [_append_channel_to_socks_url(ln, ch) for ln in formatted]

    with open(out_path, "w", encoding="utf-8") as f:
        if formatted:
            f.write("\n".join(formatted) + "\n")

    top_n = max(1, int(ns.top_n))
    top_lines = formatted[:top_n]
    with open(top_path, "w", encoding="utf-8") as f:
        if top_lines:
            f.write("\n".join(top_lines) + "\n")

    console.print(f"[green][OK][/green] {out_path} ({len(results)} шт.)")
    console.print(f"[green][OK][/green] {top_path} (top {top_n})")


if __name__ == "__main__":
    main()
