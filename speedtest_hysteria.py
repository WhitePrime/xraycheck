#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Speedtest для конфигов Hysteria 2 (hy2://, hysteria2://).
Читает список из файла (например configs/hysteria), для каждого поднимает клиент Hysteria,
измеряет задержку и/или скорость загрузки, сортирует и пишет в configs/hysteria_st и configs/hysteria_st(top100).
Использует те же параметры SPEED_TEST_* что и speedtest_checker (latency / quick / full).
"""

import os
import re
import socket
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

# Импорт из hysteria_checker (поднимает HYSTERIA_CMD и т.д.)
from hysteria_checker import (
    HYSTERIA_PORT_WAIT,
    HYSTERIA_STARTUP_POLL,
    HYSTERIA_STARTUP_WAIT,
    build_hysteria_config,
    kill_hysteria,
    run_hysteria,
)
from lib.config import (
    MAX_WORKERS,
    OUTPUT_DIR,
    SPEED_TEST_DOWNLOAD_TIMEOUT,
    SPEED_TEST_DOWNLOAD_URL_MEDIUM,
    SPEED_TEST_DOWNLOAD_URL_SMALL,
    SPEED_TEST_METRIC,
    SPEED_TEST_MODE,
    SPEED_TEST_REQUESTS,
    SPEED_TEST_TIMEOUT,
    SPEED_TEST_URL,
    SPEED_TEST_WORKERS,
    VERIFY_HTTPS_SSL,
)
from lib.parsing import parse_proxy_url
from lib.port_pool import return_port, take_port
from lib.utils import check_response_valid, make_request

import requests

console = Console()

_LATENCY_PREFIX_RE = re.compile(r"^\[\d+ms\]\s*", re.MULTILINE)
_HY2_PREFIXES = ("hy2://", "hysteria2://", "hysteria://")


def _strip_latency_prefix(line: str) -> str:
    return _LATENCY_PREFIX_RE.sub("", line).strip()


def _wait_for_port(host: str, port: int, max_wait: float, poll_interval: float = 0.05) -> bool:
    deadline = time.perf_counter() + max_wait
    while time.perf_counter() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.3):
                return True
        except (socket.error, socket.gaierror, OSError):
            time.sleep(poll_interval)
    return False


def _test_download_speed(proxies: dict, url: str, timeout_sec: int) -> float | None:
    try:
        verify = VERIFY_HTTPS_SSL if url.lower().startswith("https://") else True
        start_time = time.perf_counter()
        r = requests.get(
            url,
            proxies=proxies,
            timeout=(5, timeout_sec),
            stream=True,
            allow_redirects=False,
            verify=verify,
        )
        if r.status_code != 200:
            return None
        downloaded = 0
        for chunk in r.iter_content(chunk_size=8192):
            if chunk:
                downloaded += len(chunk)
            if time.perf_counter() - start_time > timeout_sec:
                break
        elapsed = time.perf_counter() - start_time
        if elapsed < 0.3:
            return None
        return round((downloaded * 8) / (elapsed * 1_000_000), 2)
    except requests.RequestException:
        return None


def speed_test_hysteria_key(
    proxy_line: str,
    timeout: float,
    metric: str,
    requests_count: int,
    test_url: str,
    mode: str = "latency",
    download_timeout: int = 30,
    download_url_small: str = "",
    download_url_medium: str = "",
) -> tuple[str, float] | None:
    """
    Speedtest одного Hysteria2-ключа: поднимает клиент, меряет задержку и/или скорость.
    Возвращает (строка_ключа, score): score = latency_ms (меньше лучше) или speed_mbps (больше лучше).
    """
    parsed = parse_proxy_url(proxy_line)
    if not parsed or parsed.get("protocol") not in ("hysteria", "hysteria2"):
        return None

    port = take_port()
    if port is None:
        return None

    fd, config_path = tempfile.mkstemp(suffix=".yaml", prefix="hy_st_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(build_hysteria_config(proxy_line, port))
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        return_port(port)
        return None

    proc = run_hysteria(config_path)
    if proc is None:
        return_port(port)
        try:
            os.unlink(config_path)
        except FileNotFoundError:
            pass
        return None

    try:
        waited = 0.0
        while waited < HYSTERIA_STARTUP_WAIT:
            if proc.poll() is not None:
                return_port(port)
                return None
            time.sleep(HYSTERIA_STARTUP_POLL)
            waited += HYSTERIA_STARTUP_POLL

        if not _wait_for_port("127.0.0.1", port, max_wait=min(HYSTERIA_PORT_WAIT, timeout + 5)):
            return None

        proxies = {
            "http": f"socks5h://127.0.0.1:{port}",
            "https": f"socks5h://127.0.0.1:{port}",
        }
        deadline = time.perf_counter() + timeout
        response_times: list[float] = []
        per_request_timeout = max(1.0, (timeout - 0.2) / max(1, requests_count))
        connect_t = min(5, max(1.0, per_request_timeout * 0.5))
        read_t = min(15, max(3.0, per_request_timeout * 0.6))

        for _ in range(requests_count):
            if time.perf_counter() >= deadline:
                break
            resp, elapsed, err = make_request(test_url, proxies, (connect_t, read_t))
            if resp and not err and check_response_valid(resp, 0, test_url):
                response_times.append(elapsed * 1000.0)

        if not response_times:
            return None

        avg_latency_ms = sum(response_times) / len(response_times)

        if mode == "quick" and download_url_small:
            speed_mbps = _test_download_speed(proxies, download_url_small, min(10, download_timeout))
            if speed_mbps is not None:
                return (proxy_line, speed_mbps)
            return None
        if mode == "full" and download_url_medium:
            speed_mbps = _test_download_speed(proxies, download_url_medium, download_timeout)
            if speed_mbps is not None:
                return (proxy_line, speed_mbps)
            return None

        if mode == "latency" or not (download_url_small or download_url_medium):
            if metric == "throughput":
                return (proxy_line, 100000.0 / avg_latency_ms if avg_latency_ms > 0 else 0)
            return (proxy_line, avg_latency_ms)
        return (proxy_line, avg_latency_ms)
    finally:
        kill_hysteria(proc)
        try:
            os.unlink(config_path)
        except FileNotFoundError:
            pass
        return_port(port)


def _load_lines(path: str) -> list[str]:
    with open(path, encoding="utf-8") as f:
        lines = f.readlines()
    out = []
    for raw in lines:
        line = _strip_latency_prefix(raw)
        if line and any(line.startswith(p) for p in _HY2_PREFIXES):
            out.append(line)
    return out


def main() -> None:
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    input_path = args[0] if args else os.path.join("configs", "hysteria")
    if not os.path.isfile(input_path):
        console.print(f"[red]File ne najden: {input_path}[/red]")
        console.print("Usage: python speedtest_hysteria.py [configs/hysteria]")
        sys.exit(1)

    lines = _load_lines(input_path)
    if not lines:
        console.print("[yellow]Net klyuchej v fajle.[/yellow]")
        sys.exit(0)

    out_dir = os.environ.get("HYSTERIA_OUTPUT_DIR", OUTPUT_DIR or "configs")
    base_name = Path(input_path).stem
    if base_name == "hysteria":
        out_name = "hysteria_st"
    else:
        out_name = f"{base_name}_st"
    output_path = os.path.join(out_dir, out_name)
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    workers = min(SPEED_TEST_WORKERS, MAX_WORKERS)
    config_table = Table(show_header=False, box=None, padding=(0, 1))
    config_table.add_row("[cyan]Входной файл[/cyan]", input_path)
    config_table.add_row("[cyan]Файл результата[/cyan]", output_path)
    config_table.add_row("[cyan]Конфигов к проверке[/cyan]", str(len(lines)))
    config_table.add_row("[cyan]Режим[/cyan]", SPEED_TEST_MODE)
    config_table.add_row("[cyan]Метрика[/cyan]", SPEED_TEST_METRIC)
    config_table.add_row("[cyan]Таймаут (с)[/cyan]", str(SPEED_TEST_TIMEOUT))
    config_table.add_row("[cyan]Потоков[/cyan]", str(workers))
    console.print(Panel(config_table, title="[bold cyan]Параметры спидтеста[/bold cyan]", border_style="cyan"))
    console.print()

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
        task = progress.add_task("[cyan]Speedtest Hysteria2...[/cyan]", total=len(lines))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(
                    speed_test_hysteria_key,
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
        console.print("[yellow]Net uspeshnyh rezultatov.[/yellow]")
        sys.exit(0)

    sort_by_speed = SPEED_TEST_MODE in ("quick", "full") or SPEED_TEST_METRIC == "throughput"
    results.sort(key=lambda x: x[1], reverse=sort_by_speed)

    out_lines = [_strip_latency_prefix(item[0]) for item in results]
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(out_lines))
    console.print(f"[green]OK[/green] Rezultaty: [bold]{output_path}[/bold] ({len(results)} konfigov)")

    top100_path = os.path.join(out_dir, f"{out_name}(top100)")
    with open(top100_path, "w", encoding="utf-8") as f:
        f.write("\n".join(out_lines[:100]))
    console.print(f"[green]OK[/green] Top100: [bold]{top100_path}[/bold]")

    best, worst = results[0][1], results[-1][1]
    if sort_by_speed:
        console.print(f"[cyan]Skorost:[/cyan] {worst:.2f} - {best:.2f} Mbps, vremya {elapsed:.1f}s")
    else:
        console.print(f"[cyan]Zaderzhka:[/cyan] {best:.0f} - {worst:.0f} ms, vremya {elapsed:.1f}s")


if __name__ == "__main__":
    main()
