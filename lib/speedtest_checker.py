#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Speedtest уже проверенных конфигов (второй уровень).
Читает список из файла (например configs/available), для каждого ключа измеряет задержку/скорость
(не более SPEED_TEST_TIMEOUT секунд на конфиг), сортирует по скорости и пишет в файлы с суффиксом _st.
Управление: SPEED_TEST_ENABLED, SPEED_TEST_TIMEOUT, SPEED_TEST_METRIC, SPEED_TEST_OUTPUT.
"""

import logging
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from lib.config import (
    MAX_WORKERS,
    MIN_SPEED_THRESHOLD_MBPS,
    SPEED_TEST_DEBUG,
    OUTPUT_DIR,
    SPEED_TEST_DOWNLOAD_TIMEOUT,
    SPEED_TEST_DOWNLOAD_URL_MEDIUM,
    SPEED_TEST_DOWNLOAD_URL_SMALL,
    SPEED_TEST_ENABLED,
    SPEED_TEST_METRIC,
    SPEED_TEST_MODE,
    SPEED_TEST_OUTPUT,
    SPEED_TEST_REQUESTS,
    SPEED_TEST_TIMEOUT,
    SPEED_TEST_URL,
    SPEED_TEST_WORKERS,
)
from lib.speedtest import speed_test_key
from lib.xray_manager import ensure_xray

console = Console()

_LATENCY_PREFIX_RE = re.compile(r"^\[\d+ms\]\s*", re.MULTILINE)
_PROTOCOL_PREFIXES = ("vless://", "vmess://", "trojan://", "ss://", "hysteria://", "hysteria2://", "hy2://")


def _strip_latency_prefix(line: str) -> str:
    return _LATENCY_PREFIX_RE.sub("", line).strip()


def _is_proxy_line(line: str) -> bool:
    s = line.strip()
    if not s or s.startswith("#"):
        return False
    s = _strip_latency_prefix(s)
    return any(s.startswith(p) for p in _PROTOCOL_PREFIXES)


def _load_lines(path: str) -> list[str]:
    with open(path, encoding="utf-8") as f:
        lines = f.readlines()
    out = []
    for raw in lines:
        line = _strip_latency_prefix(raw)
        if line and any(line.startswith(p) for p in _PROTOCOL_PREFIXES):
            out.append(line)
    return out


def main() -> None:
    if not SPEED_TEST_ENABLED:
        console.print("[yellow]Speedtest отключён (SPEED_TEST_ENABLED=false).[/yellow]")
        sys.exit(0)

    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if not args:
        console.print("[red]Укажите файл со списком конфигов, например:[/red] python speedtest_checker.py configs/available")
        sys.exit(1)
    input_path = args[0]
    if not os.path.isfile(input_path):
        console.print(f"[red]Файл не найден: {input_path}[/red]")
        sys.exit(1)

    if SPEED_TEST_DEBUG:
        logging.basicConfig(level=logging.INFO, format="%(message)s")
        logging.getLogger("lib.speedtest").setLevel(logging.INFO)

    lines = _load_lines(input_path)
    if not lines:
        console.print("[yellow]Нет ключей в файле.[/yellow]")
        sys.exit(0)

    console.print("[cyan]Проверка xray...[/cyan]")
    if not ensure_xray():
        console.print("[bold red]Ошибка: xray недоступен.[/bold red]")
        console.print("Установите Xray-core и добавьте в PATH или задайте XRAY_PATH в .env")
        sys.exit(1)
    console.print("[green][OK][/green] xray готов.\n")

    base_name = Path(input_path).stem
    out_name = f"{base_name}_st"
    out_dir = OUTPUT_DIR or "configs"
    output_path = os.path.join(out_dir, out_name)
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    workers = min(SPEED_TEST_WORKERS, MAX_WORKERS)
    console.print(
        f"[cyan]Speedtest:[/cyan] {len(lines)} ключей, режим={SPEED_TEST_MODE}, метрика={SPEED_TEST_METRIC}, "
        f"таймаут={SPEED_TEST_TIMEOUT}с, воркеров={workers}"
    )
    time_start = time.perf_counter()

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
        task = progress.add_task("[cyan]Speedtest...[/cyan]", total=len(lines))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(
                    speed_test_key,
                    line,
                    SPEED_TEST_TIMEOUT,
                    SPEED_TEST_METRIC,
                    SPEED_TEST_REQUESTS,
                    SPEED_TEST_URL,
                    mode=SPEED_TEST_MODE,
                    download_timeout=SPEED_TEST_DOWNLOAD_TIMEOUT,
                    download_url_small=SPEED_TEST_DOWNLOAD_URL_SMALL,
                    download_url_medium=SPEED_TEST_DOWNLOAD_URL_MEDIUM,
                ): line
                for line in lines
            }
            for future in as_completed(futures):
                progress.advance(task)
                try:
                    pair = future.result()
                    if pair is not None:
                        results.append(pair)
                except Exception:
                    pass

    elapsed = time.perf_counter() - time_start
    if not results:
        console.print("[yellow]Нет успешных результатов speedtest.[/yellow]")
        sys.exit(0)

    sort_by_speed = SPEED_TEST_MODE in ("quick", "full") or SPEED_TEST_METRIC == "throughput"
    reverse = sort_by_speed
    results.sort(key=lambda x: x[1], reverse=reverse)

    if MIN_SPEED_THRESHOLD_MBPS > 0 and sort_by_speed:
        results = [(line, score) for line, score in results if score >= MIN_SPEED_THRESHOLD_MBPS]
        if not results:
            console.print(f"[yellow]Нет ключей со скоростью >= {MIN_SPEED_THRESHOLD_MBPS} Mbps.[/yellow]")
            sys.exit(0)
        console.print(f"[dim]Отфильтровано по мин. скорости {MIN_SPEED_THRESHOLD_MBPS} Mbps: {len(results)} ключей[/dim]")

    out_lines = [_strip_latency_prefix(item[0]) for item in results]
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(out_lines))
    console.print(f"[green][OK][/green] Результаты сохранены в: [bold]{output_path}[/bold] ({len(results)} ключей, по скорости)")

    top100_path = os.path.join(out_dir, f"{out_name}(top100)")
    top100_lines = out_lines[:100]
    with open(top100_path, "w", encoding="utf-8") as f:
        f.write("\n".join(top100_lines))
    console.print(f"[green][OK][/green] Top100 по скорости: [bold]{top100_path}[/bold]")

    if results:
        best = results[0][1]
        worst = results[-1][1]
        if sort_by_speed:
            console.print(f"[cyan]Скорость:[/cyan] от {worst:.2f} до {best:.2f} Mbps, время {elapsed:.1f}с")
        else:
            console.print(f"[cyan]Задержка:[/cyan] от {best:.0f}мс до {worst:.0f}мс, время {elapsed:.1f}с")


if __name__ == "__main__":
    main()
