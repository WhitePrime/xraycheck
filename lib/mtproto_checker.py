#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Проверка доступности и "скорости" MTProto-прокси с комбинированной метрикой.

Скрипт читает список MTProto-прокси из текстового файла, для каждого прокси
несколько раз измеряет время установления TCP-соединения (RTT) и рассчитывает
комбинированный скор, учитывающий:
  - среднюю задержку (latency),
  - стабильность (долю успешных подключений),
  - "джиттер" (разброс задержек между попытками).

По результатам формируются файлы в директории OUTPUT_DIR (по умолчанию `configs`):
  - mtproto          - все доступные и достаточно стабильные прокси,
                       отсортированные по комбинированному скору
  - mtproto(top100)  - топ-100 по скору (самые "быстрые и стабильные")

В обоих файлах каждая строка содержит **только сам прокси** в исходном формате
(`tg://proxy?...`, `host:port`, `host:port:secret`) - без префиксов и комментариев.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

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

console = Console()

_LATENCY_PREFIX_RE = re.compile(r"^\[\d+ms\]\s*", re.MULTILINE)

_ZERO_WIDTH = ("\u200b", "\u200c", "\u200d", "\ufeff")

_HOST_HAS_FORBIDDEN_RE = re.compile(r"[\s/\\@]")
_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

_URLISH_JUNK_TAIL_RE = re.compile(r"[)\]\[}`*_|~<>«»„“”'\"…。，、؛؛،⚡✨]+$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}\.?$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")


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
    """Убирает префикс вида `[123ms]` в начале строки, если он есть."""
    return _LATENCY_PREFIX_RE.sub("", line).strip()


def _normalize_raw_lines(lines: list[str]) -> list[str]:
    """Нормализует сырые строки: убирает префиксы, пустые строки и комментарии."""
    out: list[str] = []
    for raw in lines:
        line = _strip_latency_prefix(raw).strip()
        for zw in _ZERO_WIDTH:
            line = line.replace(zw, "")
        if not line or line.startswith("#"):
            continue
        # Часто в списках встречается мусор вокруг ссылки (markdown/текст). Вытаскиваем tg://proxy,
        # если она присутствует в строке.
        if "tg://proxy?" in line:
            line = line[line.find("tg://proxy?") :].strip()
        out.append(line)
    return out


def _load_raw_lines(path: str) -> list[str]:
    """Загружает строки из локального файла, отбрасывая пустые и комментарии."""
    with open(path, encoding="utf-8") as f:
        lines = f.readlines()
    return _normalize_raw_lines(lines)


def _load_raw_lines_from_text(text: str) -> list[str]:
    """Загружает строки из текстового содержимого (например, скачанного по HTTP)."""
    return _normalize_raw_lines(text.splitlines())


def _normalize_host(host: str) -> Optional[str]:
    h = (host or "").strip()
    if not h:
        return None
    # server= может быть в квадратных скобках для IPv6
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1].strip()
    h = h.rstrip(".")
    if not h:
        return None
    if _HOST_HAS_FORBIDDEN_RE.search(h):
        return None
    # IP
    try:
        ipaddress.ip_address(h)
        return h
    except ValueError:
        pass
    # Домен
    if _DOMAIN_RE.match(h):
        return h.lower()
    return None


def _normalize_port(port: int) -> Optional[int]:
    if 1 <= port <= 65535:
        return port
    return None


def _normalize_secret(secret: str, strict: bool) -> Optional[str]:
    s = (secret or "").strip()
    if not s:
        return None

    # parse_qs трактует '+' как пробел. Встречается в base64 секретах.
    if " " in s and ("+" not in s):
        candidate = s.replace(" ", "+")
        if _B64_RE.match(candidate) or _B64URL_RE.match(candidate):
            s = candidate

    # Снимаем распространённые markdown/пунктуационные хвосты, но только с конца.
    s = _URLISH_JUNK_TAIL_RE.sub("", s).strip()

    if not s:
        return None

    # 1) HEX (официальный формат) - берём валидный префикс, чтобы отрезать мусор в конце.
    m_hex = re.match(r"^[0-9a-fA-F]+", s)
    if m_hex:
        cand = m_hex.group(0)
        if cand and len(cand) >= 32 and len(cand) % 2 == 0:
            return cand.lower()
        if cand and not strict and len(cand) >= 16:
            return cand.lower()

    # 2) base64url - берём валидный префикс (часто в списках есть хвост вроде `)[**`)
    cand_b64url: Optional[str] = None
    m_b64url = re.match(r"^[A-Za-z0-9_-]+={0,2}", s)
    if m_b64url:
        cand = m_b64url.group(0)
        if cand and 8 <= len(cand) <= 512 and (_B64URL_RE.match(cand) is not None):
            cand_b64url = cand

    # 3) base64 - аналогично
    cand_b64: Optional[str] = None
    m_b64 = re.match(r"^[A-Za-z0-9+/]+={0,2}", s)
    if m_b64:
        cand = m_b64.group(0)
        if cand and 8 <= len(cand) <= 512 and (_B64_RE.match(cand) is not None):
            cand_b64 = cand

    if cand_b64url and cand_b64:
        return cand_b64 if len(cand_b64) >= len(cand_b64url) else cand_b64url
    if cand_b64:
        return cand_b64
    if cand_b64url:
        return cand_b64url

    return None


def _parse_mtproto(line: str, *, strict: bool, allow_incomplete: bool) -> Optional[tuple[str, int, str, tuple[str, int, str]]]:
    """
    Разбор строки MTProto-прокси.

    Поддерживаемые форматы:
      - tg://proxy?server=HOST&port=PORT&secret=XXXX
      - https://t.me/proxy?server=HOST&port=PORT&secret=XXXX
      - HOST:PORT
      - HOST:PORT:SECRET
    """
    s = line.strip()
    if not s:
        return None

    if s.startswith("tg://") or s.startswith("http://") or s.startswith("https://"):
        parsed = urlparse(s)
        if parsed.scheme in ("http", "https") and parsed.path not in ("/proxy", "/proxy/", "proxy", "proxy/"):
            return None
        qs = parse_qs(parsed.query)
        server = qs.get("server", [None])[0]
        port_str = qs.get("port", [None])[0]
        secret = qs.get("secret", [None])[0]
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
        secret_n = _normalize_secret(secret or "", strict=strict)
        if secret_n is None:
            if allow_incomplete:
                normalized = f"{host_n}:{port_n}"
                key = (host_n, port_n, "")
                return host_n, port_n, normalized, key
            return None
        normalized = f"tg://proxy?server={host_n}&port={port_n}&secret={secret_n}"
        key = (host_n, port_n, secret_n)
        return host_n, port_n, normalized, key

    # host:port или host:port:secret
    if ":" in s:
        parts = s.split(":")
        if len(parts) >= 2:
            host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                return None
            host_n = _normalize_host(host)
            port_n = _normalize_port(port)
            if host_n is None or port_n is None:
                return None
            secret_part = parts[2] if len(parts) >= 3 else ""
            if secret_part:
                secret_n = _normalize_secret(secret_part, strict=strict)
                if secret_n is None:
                    return None
                normalized = f"tg://proxy?server={host_n}&port={port_n}&secret={secret_n}"
                key = (host_n, port_n, secret_n)
                return host_n, port_n, normalized, key
            if allow_incomplete:
                normalized = f"{host_n}:{port_n}"
                key = (host_n, port_n, "")
                return host_n, port_n, normalized, key
            return None

    return None


def _append_channel_to_proxy_url(line: str, channel: str) -> str:
    """Добавляет &channel=... к строке tg://proxy или https://t.me/proxy; иначе возвращает строку без изменений."""
    s = line.strip()
    if not s or s.startswith("#"):
        return line
    try:
        p = urlparse(s)
    except Exception:
        return line
    if p.scheme == "tg":
        if p.netloc != "proxy":
            return line
    elif p.scheme in ("http", "https"):
        if (p.netloc or "").lower() not in ("t.me", "telegram.me"):
            return line
        if (p.path or "").rstrip("/") != "/proxy":
            return line
    else:
        return line
    qs = parse_qs(p.query or "", keep_blank_values=True)
    qs.pop("channel", None)
    base_query = urlencode(qs, doseq=True)
    new_query = (base_query + f"&channel={channel}") if base_query else f"channel={channel}"
    return urlunparse(p._replace(query=new_query))


def _check_proxy(
    host: str,
    port: int,
    timeout: float,
    attempts: int,
    min_success_rate: float,
    jitter_scale_ms: float,
) -> Optional[float]:
    """
    «Спидтест» MTProto-прокси по TCP с комбинированной метрикой.

    Делает несколько попыток TCP-подключения и возвращает один скор (float),
    который учитывает:
      - среднюю задержку,
      - долю успешных подключений,
      - джиттер между попытками.

    Чем меньше скор, тем «лучше» прокси. При слишком низкой стабильности
    (success_rate < _MIN_SUCCESS_RATE) возвращает None.
    """
    total_attempts = max(1, attempts)
    latencies: list[float] = []

    for _ in range(total_attempts):
        try:
            start = time.perf_counter()
            with socket.create_connection((host, port), timeout=timeout):
                latencies.append((time.perf_counter() - start) * 1000.0)
        except (OSError, socket.error):
            continue

    if not latencies:
        return None

    success_count = len(latencies)
    fail_count = total_attempts - success_count
    success_rate = success_count / total_attempts

    # Слишком нестабильные прокси отбрасываем сразу.
    if success_rate < min_success_rate:
        return None

    avg_latency = sum(latencies) / success_count
    if len(latencies) > 1:
        jitter = max(latencies) - min(latencies)
    else:
        jitter = 0.0

    # Чем больше джиттер, тем сильнее штраф.
    jitter_factor = 1.0 + (jitter / jitter_scale_ms) if jitter_scale_ms > 0 else 1.0
    # Дополнительный мягкий штраф за неудачные попытки (если они были).
    fail_penalty = 1.0 + (fail_count / total_attempts) if fail_count > 0 else 1.0

    score = avg_latency * jitter_factor * fail_penalty
    return score


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="mtproto_checker.py",
        description="Проверка MTProto-прокси по TCP с метрикой latency/stability/jitter.",
    )
    parser.add_argument("source", help="Источник списка: локальный файл или URL")
    parser.add_argument(
        "--workers",
        type=int,
        default=MAX_WORKERS,
        help=f"Макс. число потоков (по умолчанию: {MAX_WORKERS})",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=float(CONNECT_TIMEOUT),
        help=f"Таймаут TCP connect в секундах (по умолчанию: {CONNECT_TIMEOUT})",
    )
    parser.add_argument(
        "--attempts",
        type=int,
        default=_env_int("MTPROTO_ATTEMPTS", 3),
        help="Попыток TCP-подключения на прокси (env MTPROTO_ATTEMPTS, default 3)",
    )
    parser.add_argument(
        "--min-success-rate",
        type=float,
        default=_env_float("MTPROTO_MIN_SUCCESS_RATE", 0.67),
        help="Мин. доля успешных попыток 0..1 (env MTPROTO_MIN_SUCCESS_RATE, default 0.67)",
    )
    parser.add_argument(
        "--jitter-scale-ms",
        type=float,
        default=_env_float("MTPROTO_JITTER_SCALE_MS", 300.0),
        help="Шкала штрафа джиттера (env MTPROTO_JITTER_SCALE_MS, default 300)",
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=_env_int("MTPROTO_TOP_N", 100),
        help="Размер топа (env MTPROTO_TOP_N, default 100)",
    )
    parser.add_argument(
        "--max-candidates",
        type=int,
        default=_env_int("MTPROTO_MAX_CANDIDATES", 0),
        help="Ограничить кол-во кандидатов до проверки (0 = без ограничений)",
    )
    parser.add_argument(
        "--allow-incomplete",
        action="store_true",
        default=_env_bool("MTPROTO_ALLOW_INCOMPLETE", False),
        help="Разрешить строки без secret (HOST:PORT / tg:// без secret)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        default=_env_bool("MTPROTO_STRICT", True),
        help="Строгая нормализация/валидация входа и выход только чистых ссылок",
    )
    parser.add_argument(
        "--no-strict",
        action="store_false",
        dest="strict",
        help="Ослабить валидацию (не рекомендуется)",
    )

    ns = parser.parse_args()
    source = ns.source

    # Поддержка как локальных файлов, так и HTTP(S) ссылок
    if source.startswith(("http://", "https://")):
        try:
            resp = requests.get(source, timeout=30)
        except requests.RequestException as e:
            console.print(f"[red]Ошибка при загрузке списка по URL:[/red] {e}")
            sys.exit(1)
        if resp.status_code != 200:
            console.print(
                f"[red]Не удалось загрузить список:[/red] HTTP {resp.status_code} "
                f"для URL {source}"
            )
            sys.exit(1)
        lines = _load_raw_lines_from_text(resp.text)
        input_label = source
    else:
        input_path = source
        if not os.path.isfile(input_path):
            console.print(f"[red]Файл не найден: {input_path}[/red]")
            sys.exit(1)
        lines = _load_raw_lines(input_path)
        input_label = input_path
    if not lines:
        console.print("[yellow]Нет прокси в источнике.[/yellow]")
        sys.exit(0)

    # При режиме merge удаляем полные дубликаты строк до проверки
    if MODE == "merge":
        seen: set[str] = set()
        deduped_lines: list[str] = []
        for line in lines:
            if line in seen:
                continue
            seen.add(line)
            deduped_lines.append(line)
        if not deduped_lines:
            console.print("[yellow]После дедупликации не осталось ни одного MTProto-прокси.[/yellow]")
            sys.exit(0)
        if len(deduped_lines) < len(lines):
            console.print(
                f"[dim]Дедупликация (MODE=merge): {len(lines) - len(deduped_lines)} дубликатов удалено, "
                f"{len(deduped_lines)} уникальных строк.[/dim]"
            )
        lines = deduped_lines

    parsed: list[tuple[str, int, str]] = []
    seen_keys: set[tuple[str, int, str]] = set()
    for line in lines:
        parsed_data = _parse_mtproto(line, strict=ns.strict, allow_incomplete=ns.allow_incomplete)
        if parsed_data is None:
            continue
        host, port, normalized, key = parsed_data
        if key in seen_keys:
            continue
        seen_keys.add(key)
        parsed.append((host, port, normalized))

    if ns.max_candidates and ns.max_candidates > 0 and len(parsed) > ns.max_candidates:
        parsed = parsed[: ns.max_candidates]

    if not parsed:
        console.print("[yellow]Не удалось распознать ни одного MTProto-прокси.[/yellow]")
        sys.exit(0)

    workers = min(max(1, int(ns.workers)), len(parsed))
    timeout = max(1.0, float(ns.timeout))
    attempts = max(1, int(ns.attempts))
    min_success_rate = max(0.0, min(1.0, float(ns.min_success_rate)))
    jitter_scale_ms = max(0.0, float(ns.jitter_scale_ms))

    console.print(
        f"[cyan]Speedtest MTProto:[/cyan] {len(parsed)} прокси, таймаут={timeout:.1f}с, "
        f"воркеров={workers}, попыток на прокси={attempts}, strict={'on' if ns.strict else 'off'}"
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
        task = progress.add_task("[cyan]Проверка прокси...[/cyan]", total=len(parsed))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(
                    _check_proxy,
                    host,
                    port,
                    timeout,
                    attempts,
                    min_success_rate,
                    jitter_scale_ms,
                ): original
                for host, port, original in parsed
            }
            for future in as_completed(futures):
                progress.advance(task)
                original = futures[future]
                try:
                    score = future.result()
                except Exception:
                    score = None
                if score is not None:
                    results.append((original, score))

    if not results:
        console.print("[yellow]Нет доступных MTProto-прокси.[/yellow]")
        sys.exit(0)

    # Сортируем по комбинированному скору (меньше - лучше)
    results.sort(key=lambda x: x[1])

    # Пишем рядом с остальными конфигурациями (OUTPUT_DIR, по умолчанию configs)
    output_dir = OUTPUT_DIR or "configs"
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    output_basename = os.environ.get("MTPROTO_OUTPUT_BASENAME", "").strip() or "mtproto"
    out_path = os.path.join(output_dir, output_basename)
    top100_path = os.path.join(output_dir, output_basename + "(top100)")

    # Полный список доступных прокси (только нормализованные строки прокси)
    formatted_all = [line for line, _ in results]
    channel_tag = os.environ.get("MTPROTO_CHANNEL_TAG", "").strip()
    if channel_tag:
        formatted_all = [_append_channel_to_proxy_url(ln, channel_tag) for ln in formatted_all]
    with open(out_path, "w", encoding="utf-8") as f:
        if formatted_all:
            f.write("\n".join(formatted_all) + "\n")

    # Топ-100 по скору
    top_n = max(1, int(ns.top_n))
    formatted_top = formatted_all[:top_n]
    with open(top100_path, "w", encoding="utf-8") as f:
        if formatted_top:
            f.write("\n".join(formatted_top) + "\n")

    console.print(
        f"[green][OK][/green] Рабочие прокси сохранены в [bold]{out_path}[/bold] "
        f"({len(results)} шт.)."
    )
    console.print(
        f"[green][OK][/green] Top{top_n} по скору сохранён в [bold]{top100_path}[/bold]."
    )


if __name__ == "__main__":
    main()

