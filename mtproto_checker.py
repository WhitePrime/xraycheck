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

import os
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse

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

# Число попыток TCP-подключения к одному прокси для оценки стабильности/джиттера.
_ATTEMPTS_PER_PROXY = int(os.environ.get("MTPROTO_ATTEMPTS", "3"))
# Минимальная доля успешных подключений (0.0-1.0), ниже - прокси считается нестабильным.
_MIN_SUCCESS_RATE = float(os.environ.get("MTPROTO_MIN_SUCCESS_RATE", "0.67"))
# Масштаб для штрафа за джиттер: чем меньше значение, тем сильнее влияние разброса задержек.
_JITTER_SCALE_MS = float(os.environ.get("MTPROTO_JITTER_SCALE_MS", "300.0"))


def _strip_latency_prefix(line: str) -> str:
    """Убирает префикс вида `[123ms]` в начале строки, если он есть."""
    return _LATENCY_PREFIX_RE.sub("", line).strip()


def _normalize_raw_lines(lines: list[str]) -> list[str]:
    """Нормализует сырые строки: убирает префиксы, пустые строки и комментарии."""
    out: list[str] = []
    for raw in lines:
        line = _strip_latency_prefix(raw).strip()
        if not line or line.startswith("#"):
            continue
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


def _parse_mtproto(line: str) -> Optional[tuple[str, int]]:
    """
    Разбор строки MTProto-прокси.

    Поддерживаемые форматы:
      - tg://proxy?server=HOST&port=PORT&secret=XXXX
      - HOST:PORT
      - HOST:PORT:SECRET
    """
    s = line.strip()
    if not s:
        return None

    if s.startswith("tg://"):
        parsed = urlparse(s)
        qs = parse_qs(parsed.query)
        server = qs.get("server", [None])[0]
        port_str = qs.get("port", [None])[0]
        if not server or not port_str:
            return None
        try:
            port = int(port_str)
        except ValueError:
            return None
        return server, port

    # host:port или host:port:secret
    if ":" in s:
        parts = s.split(":")
        if len(parts) >= 2:
            host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                return None
            return host, port

    return None


def _check_proxy(host: str, port: int, timeout: float, attempts: int) -> Optional[float]:
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
    if success_rate < _MIN_SUCCESS_RATE:
        return None

    avg_latency = sum(latencies) / success_count
    if len(latencies) > 1:
        jitter = max(latencies) - min(latencies)
    else:
        jitter = 0.0

    # Чем больше джиттер, тем сильнее штраф.
    jitter_factor = 1.0 + (jitter / _JITTER_SCALE_MS) if _JITTER_SCALE_MS > 0 else 1.0
    # Дополнительный мягкий штраф за неудачные попытки (если они были).
    fail_penalty = 1.0 + (fail_count / total_attempts) if fail_count > 0 else 1.0

    score = avg_latency * jitter_factor * fail_penalty
    return score


def main() -> None:
    # Позиционный аргумент - путь к файлу со списком прокси или URL
    args = [a for a in sys.argv[1:] if a and not a.startswith("-")]
    if not args:
        console.print(
            "[red]Укажите источник списка MTProto-прокси (файл или URL), например:[/red] "
            "python mtproto_checker.py mtproto_source.txt\n"
            "python mtproto_checker.py https://example.com/mtproto.txt"
        )
        sys.exit(1)

    source = args[0]

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
    for line in lines:
        parsed_data = _parse_mtproto(line)
        if parsed_data is None:
            continue
        host, port = parsed_data
        parsed.append((host, port, line))

    if not parsed:
        console.print("[yellow]Не удалось распознать ни одного MTProto-прокси.[/yellow]")
        sys.exit(0)

    workers = min(MAX_WORKERS, len(parsed))
    timeout = max(1.0, float(CONNECT_TIMEOUT))

    console.print(
        f"[cyan]Speedtest MTProto:[/cyan] {len(parsed)} прокси, таймаут={timeout:.1f}с, "
        f"воркеров={workers}, попыток на прокси={_ATTEMPTS_PER_PROXY}"
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
                executor.submit(_check_proxy, host, port, timeout, _ATTEMPTS_PER_PROXY): original
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

    out_path = os.path.join(output_dir, "mtproto")
    top100_path = os.path.join(output_dir, "mtproto(top100)")

    # Полный список доступных прокси (только сами строки прокси)
    formatted_all = [line for line, _ in results]
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(formatted_all))

    # Топ-100 по скору
    top_n = 100
    formatted_top = formatted_all[:top_n]
    with open(top100_path, "w", encoding="utf-8") as f:
        f.write("\n".join(formatted_top))

    console.print(
        f"[green][OK][/green] Рабочие прокси сохранены в [bold]{out_path}[/bold] "
        f"({len(results)} шт.)."
    )
    console.print(
        f"[green][OK][/green] Top{top_n} по скору сохранён в [bold]{top100_path}[/bold]."
    )


if __name__ == "__main__":
    main()

