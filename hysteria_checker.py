#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Чекер конфигов Hysteria 2 (hy2://, hysteria2://).
Проверки по строгости аналогичны vless_checker: STRONG_STYLE_TEST (2 успешных из 3 к gstatic/generate_204),
таймаут, макс. время ответа. Рабочие конфиги сохраняются в configs/hysteria.
Бинарник Hysteria 2: HYSTERIA_PATH или hysteria в PATH; при отсутствии скачивается в .hysteria/.
Запуск: python hysteria_checker.py [файл.txt]  (по умолчанию hys2.txt)
"""

import os
import re
import shutil
import socket
import stat
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

# Загружаем .env и конфиг
from dotenv import load_dotenv
load_dotenv()

# Строгость как в daily-check (если не задано в .env)
os.environ.setdefault("STRONG_STYLE_TEST", "true")
os.environ.setdefault("REQUIRE_HTTPS", "true")
os.environ.setdefault("STRICT_MODE", "true")
os.environ.setdefault("STRICT_MODE_REQUIRE_ALL", "true")
os.environ.setdefault("STRONG_ATTEMPTS", "2")
os.environ.setdefault("STRONG_STYLE_TIMEOUT", "12")
os.environ.setdefault("STRONG_MAX_RESPONSE_TIME", "5")

from lib.config import (
    BASE_PORT,
    CONNECT_TIMEOUT,
    MAX_LATENCY_MS,
    MAX_RESPONSE_TIME,
    MAX_WORKERS,
    MIN_RESPONSE_SIZE,
    MIN_SUCCESSFUL_REQUESTS,
    MIN_SUCCESSFUL_URLS,
    REQUEST_DELAY,
    REQUESTS_PER_URL,
    REQUIRE_HTTPS,
    STABILITY_CHECKS,
    STABILITY_CHECK_DELAY,
    STRICT_MODE,
    STRICT_MODE_REQUIRE_ALL,
    STRONG_ATTEMPTS,
    STRONG_MAX_RESPONSE_TIME,
    STRONG_STYLE_TEST,
    STRONG_STYLE_TIMEOUT,
    TEST_URLS,
    TEST_URLS_HTTPS,
    VERIFY_HTTPS_SSL,
    _CLIENT_TEST_HTTPS,
)
from lib.metrics import calculate_performance_metrics, print_statistics_table
from lib.parsing import load_keys_from_file, normalize_proxy_link, parse_proxy_url
from lib.port_pool import return_port, take_port
from lib.utils import check_response_valid, make_request
from rich.table import Table

if not VERIFY_HTTPS_SSL:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

# Путь к бинарнику: HYSTERIA_PATH, tools/hysteria в репо, PATH, или скачиваем для текущей ОС
def _ensure_hysteria() -> str:
    explicit = os.environ.get("HYSTERIA_PATH", "").strip()
    if explicit and os.path.isfile(explicit):
        return explicit
    root = Path(__file__).resolve().parent
    tools_hysteria = root / "tools" / ("hysteria.exe" if sys.platform == "win32" else "hysteria")
    if tools_hysteria.is_file():
        return str(tools_hysteria)
    in_path = shutil.which("hysteria")
    if in_path:
        return in_path
    # Скачать в .hysteria/ в корне проекта
    cache_dir = root / ".hysteria"
    if sys.platform == "win32":
        exe_name = "hysteria-windows-amd64.exe"
        local = cache_dir / "hysteria.exe"
    else:
        exe_name = "hysteria-linux-amd64" if sys.platform == "linux" else "hysteria-darwin-amd64"
        local = cache_dir / "hysteria"
    if local.is_file():
        return str(local)
    cache_dir.mkdir(parents=True, exist_ok=True)
    url = f"https://github.com/apernet/hysteria/releases/download/app/v2.4.2/{exe_name}"
    console.print(f"[dim]Скачивание Hysteria: {exe_name}...[/dim]")
    try:
        urllib.request.urlretrieve(url, local)
        if sys.platform != "win32":
            local.chmod(local.stat().st_mode | stat.S_IXUSR)
    except Exception as e:
        console.print(f"[red]Не удалось скачать Hysteria: {e}[/red]")
        console.print("Установите вручную: https://v2.hysteria.network/docs/getting-started/Installation/")
        sys.exit(1)
    return str(local)

HYSTERIA_CMD = _ensure_hysteria()
HYSTERIA_STARTUP_WAIT = float(os.environ.get("HYSTERIA_STARTUP_WAIT", "5.0"))
HYSTERIA_PORT_WAIT = float(os.environ.get("HYSTERIA_PORT_WAIT", "20.0"))
HYSTERIA_STARTUP_POLL = float(os.environ.get("HYSTERIA_STARTUP_POLL_INTERVAL", "0.2"))
OUTPUT_DIR = os.environ.get("HYSTERIA_OUTPUT_DIR", "configs")
OUTPUT_FILE = os.environ.get("HYSTERIA_OUTPUT_FILE", "hysteria")


def print_hysteria_config(input_file: str, output_path: str, total: int) -> None:
    """Выводит текущие параметры проверки в том же стиле, что и vless_checker."""
    config_table = Table(show_header=False, box=None, padding=(0, 1))
    config_table.add_row("[cyan]Режим[/cyan]", "[bold]Hysteria 2[/bold]")
    config_table.add_row("[cyan]Список ключей[/cyan]", input_file)
    config_table.add_row("[cyan]Файл результата[/cyan]", output_path)
    config_table.add_row("[cyan]Конфигов к проверке[/cyan]", str(total))
    config_table.add_row("[cyan]Потоков (многопоточность)[/cyan]", str(MAX_WORKERS))
    if STRONG_STYLE_TEST:
        config_table.add_row("[cyan]Алгоритм[/cyan]", f"строгий (минимум 2 успешных из {max(2, STRONG_ATTEMPTS)} запросов)")
        config_table.add_row("[cyan]URL проверки[/cyan]", _CLIENT_TEST_HTTPS)
        config_table.add_row("[cyan]Таймаут запроса[/cyan]", f"{STRONG_STYLE_TIMEOUT} с (connect + read)")
        config_table.add_row("[cyan]Макс. время ответа[/cyan]", f"{STRONG_MAX_RESPONSE_TIME} с")
    config_table.add_row("[cyan]Ожидание запуска клиента[/cyan]", f"{HYSTERIA_STARTUP_WAIT} с")
    config_table.add_row("[cyan]Ожидание порта SOCKS[/cyan]", f"{HYSTERIA_PORT_WAIT} с")
    config_table.add_row("[cyan]Макс. задержка в файл[/cyan]", f"{MAX_LATENCY_MS} мс")

    console.print(Panel(config_table, title="[bold cyan]Параметры проверки[/bold cyan]", border_style="cyan"))
    console.print()


def _server_url_from_link(line: str) -> str:
    """Убирает фрагмент (#комментарий) из ссылки для поля server в конфиге."""
    s = line.strip().split(maxsplit=1)[0].strip()
    if "#" in s:
        s = s.split("#", 1)[0].strip()
    return s


def build_hysteria_config(link: str, port: int) -> str:
    """Строит YAML-конфиг клиента Hysteria 2: server = URI без фрагмента, socks5 на port."""
    server_url = _server_url_from_link(link)
    # Экранируем для YAML: в двойных кавычках \ и " нужно экранировать
    escaped = server_url.replace("\\", "\\\\").replace('"', '\\"')
    return f'server: "{escaped}"\nsocks5:\n  listen: 127.0.0.1:{port}\n'


def run_hysteria(config_path: str):
    """Запускает hysteria -c config_path. Возвращает subprocess.Popen."""
    try:
        proc = subprocess.Popen(
            [HYSTERIA_CMD, "-c", config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        return proc
    except FileNotFoundError:
        return None


def _wait_for_port(host: str, port: int, max_wait: float, poll_interval: float = 0.1) -> bool:
    """Ждёт, пока порт станет доступен (SOCKS поднят)."""
    deadline = time.perf_counter() + max_wait
    while time.perf_counter() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except (socket.error, socket.gaierror, OSError):
            time.sleep(poll_interval)
    return False


def kill_hysteria(proc: subprocess.Popen) -> None:
    """Корректно завершает процесс Hysteria."""
    if proc is None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            proc.kill()
        except ProcessLookupError:
            pass


def check_hysteria_key(link: str) -> tuple[str, bool, dict]:
    """
    Проверяет один конфиг Hysteria 2: поднимает локальный прокси, делает запросы.
    Возвращает (link, ok, metrics).
    """
    metrics = {
        "response_times": [],
        "successful_urls": 0,
        "failed_urls": 0,
        "total_requests": 0,
        "successful_requests": 0,
    }
    parsed = parse_proxy_url(link)
    if not parsed or parsed.get("protocol") not in ("hysteria", "hysteria2"):
        return (link, False, metrics)

    port = take_port()
    if port is None:
        return (link, False, metrics)

    fd, config_path = tempfile.mkstemp(suffix=".yaml", prefix="hysteria_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(build_hysteria_config(link, port))
    except Exception:
        return_port(port)
        return (link, False, metrics)

    proc = run_hysteria(config_path)
    if proc is None:
        return_port(port)
        try:
            os.unlink(config_path)
        except FileNotFoundError:
            pass
        return (link, False, metrics)

    try:
        waited = 0.0
        while waited < HYSTERIA_STARTUP_WAIT:
            if proc.poll() is not None:
                return_port(port)
                return (link, False, metrics)
            time.sleep(HYSTERIA_STARTUP_POLL)
            waited += HYSTERIA_STARTUP_POLL

        if not _wait_for_port("127.0.0.1", port, max_wait=HYSTERIA_PORT_WAIT):
            return_port(port)
            return (link, False, metrics)

        proxies = {
            "http": f"socks5h://127.0.0.1:{port}",
            "https": f"socks5h://127.0.0.1:{port}",
        }
        timeout = CONNECT_TIMEOUT

        # Строгий режим: N запросов к gstatic/generate_204, проход при минимум 2 успешных из N (допуск к сетевым сбоям)
        if STRONG_STYLE_TEST:
            max_ok_time = STRONG_MAX_RESPONSE_TIME if STRONG_MAX_RESPONSE_TIME > 0 else MAX_RESPONSE_TIME
            connect_t = max(3, min(10, int(STRONG_STYLE_TIMEOUT * 0.4)))
            read_t = max(5, STRONG_STYLE_TIMEOUT - connect_t)
            timeout_strong = (connect_t, read_t)
            attempts_total = max(2, STRONG_ATTEMPTS)
            min_success = 2
            success_count = 0
            for attempt in range(attempts_total):
                if attempt > 0:
                    time.sleep(0.5)
                response, elapsed_time, error = make_request(
                    _CLIENT_TEST_HTTPS, proxies, timeout_strong
                )
                metrics["total_requests"] = metrics.get("total_requests", 0) + 1
                if response and not error and check_response_valid(response, 0, _CLIENT_TEST_HTTPS):
                    if max_ok_time > 0 and elapsed_time > max_ok_time:
                        continue
                    metrics["response_times"].append(elapsed_time)
                    success_count += 1
            if success_count >= min_success:
                metrics["successful_requests"] = success_count
                metrics["successful_urls"] = 1
                metrics["failed_urls"] = 0
                return (link, True, metrics)
            return (link, False, metrics)

        # Много URL + стабильность (как в vless_checker без STRONG_STYLE)
        all_urls = []
        if TEST_URLS:
            all_urls.extend([(url, "http") for url in TEST_URLS])
        if TEST_URLS_HTTPS:
            all_urls.extend([(url, "https") for url in TEST_URLS_HTTPS])
        if not all_urls:
            all_urls = [(_CLIENT_TEST_HTTPS, "https")]

        stability_results = []
        for stability_check in range(STABILITY_CHECKS):
            if stability_check > 0:
                time.sleep(STABILITY_CHECK_DELAY)
            successful_urls_count = 0
            for url, _ in all_urls:
                request_ok = 0
                for request_num in range(REQUESTS_PER_URL):
                    if request_num > 0:
                        time.sleep(REQUEST_DELAY)
                    response, elapsed_time, error = make_request(url, proxies, timeout)
                    metrics["total_requests"] += 1
                    if response and not error and check_response_valid(response, MIN_RESPONSE_SIZE, url):
                        if MAX_RESPONSE_TIME > 0 and elapsed_time > MAX_RESPONSE_TIME:
                            continue
                        metrics["response_times"].append(elapsed_time)
                        request_ok += 1
                        metrics["successful_requests"] += 1
                if request_ok >= MIN_SUCCESSFUL_REQUESTS:
                    successful_urls_count += 1
            passed = (
                successful_urls_count == len(all_urls)
                if (STRICT_MODE and STRICT_MODE_REQUIRE_ALL)
                else successful_urls_count >= MIN_SUCCESSFUL_URLS
            )
            if REQUIRE_HTTPS and not any(t == "https" for _, t in all_urls):
                passed = False
            stability_results.append(passed)

        if STABILITY_CHECKS > 1 and not all(stability_results):
            return (link, False, metrics)

        metrics["successful_urls"] = successful_urls_count
        metrics["failed_urls"] = len(all_urls) - successful_urls_count
        is_available = (
            successful_urls_count == len(all_urls)
            if (STRICT_MODE and STRICT_MODE_REQUIRE_ALL)
            else successful_urls_count >= MIN_SUCCESSFUL_URLS
        )
        if REQUIRE_HTTPS and not all_urls:
            is_available = False
        return (link, is_available, metrics)

    finally:
        kill_hysteria(proc)
        try:
            os.unlink(config_path)
        except FileNotFoundError:
            pass
        return_port(port)


def main():
    args = [a for a in sys.argv[1:] if a.startswith("-")]
    files_arg = [a for a in sys.argv[1:] if not a.startswith("-")]

    input_file = files_arg[0] if files_arg else "hys2.txt"
    if not os.path.isfile(input_file):
        console.print(f"[bold red]Файл не найден:[/bold red] {input_file}")
        sys.exit(1)

    keys = load_keys_from_file(input_file)
    # Только Hysteria / Hysteria2
    keys = [(link, full) for link, full in keys if link.startswith(("hy2://", "hysteria2://", "hysteria://"))]
    if not keys:
        console.print("[yellow]Нет конфигов Hysteria в файле.[/yellow]")
        sys.exit(0)

    # Дедупликация по нормализованному ключу
    seen = set()
    unique = []
    for link, full in keys:
        norm = normalize_proxy_link(link)
        if norm and norm not in seen:
            seen.add(norm)
            unique.append((link, full))

    link_to_full = {link: full for link, full in unique}
    links_only = [link for link, _ in unique]
    total = len(links_only)

    output_path = os.path.join(OUTPUT_DIR, OUTPUT_FILE)
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

    print_hysteria_config(input_file, output_path, total)

    console.print(f"[cyan]Проверка ключей из[/cyan] {input_file}")
    console.print(f"[bold]Найдено конфигов:[/bold] {total}".replace(",", " "))
    console.print()

    available = []
    available_links = set()
    all_metrics = {}
    time_start = time.perf_counter()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("({task.completed}/{task.total})"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Проверка Hysteria...[/cyan]", total=len(links_only))
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(check_hysteria_key, link): link for link in links_only}
            for future in as_completed(futures):
                link = futures[future]
                try:
                    link, ok, metrics = future.result()
                    all_metrics[link] = metrics
                    if ok:
                        full = link_to_full.get(link, link)
                        latency_ms = 0.0
                        if metrics.get("response_times"):
                            latency_ms = (sum(metrics["response_times"]) / len(metrics["response_times"])) * 1000
                        if latency_ms <= MAX_LATENCY_MS:
                            available.append((full, latency_ms))
                            available_links.add(link)
                    progress.advance(task)
                    progress.update(
                        task,
                        description=f"[cyan]Проверка Hysteria...[/cyan] [OK: {len(available)}, FAIL: {len(all_metrics) - len(available)}]",
                    )
                except Exception:
                    all_metrics[link] = {}
                    progress.advance(task)

    elapsed = time.perf_counter() - time_start
    available_sorted = sorted(available, key=lambda x: x[1])

    # Результаты для метрик (как в vless_checker)
    results_for_metrics = []
    for link, metrics in all_metrics.items():
        results_for_metrics.append({
            "key": link,
            "available": link in available_links,
            "response_times": metrics.get("response_times", []),
            "avg_response_time": statistics.mean(metrics["response_times"]) if metrics.get("response_times") else 0,
            "geolocation": None,
            "error": None,
        })
    perf_metrics = calculate_performance_metrics(results_for_metrics, all_metrics, elapsed)
    print_statistics_table(perf_metrics)

    if available_sorted:
        lines_out = [item[0] for item in available_sorted]
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines_out))
        console.print(f"\n[green][OK][/green] Результаты сохранены в: [bold]{output_path}[/bold] (отсортированы по задержке)")

        # Top100
        top100_path = os.path.join(OUTPUT_DIR, f"{OUTPUT_FILE}(top100)")
        top100_lines = lines_out[:100]
        with open(top100_path, "w", encoding="utf-8") as f:
            f.write("\n".join(top100_lines))
        lat_min = available_sorted[0][1]
        lat_max = available_sorted[min(99, len(available_sorted) - 1)][1]
        console.print(f"[cyan]Top100:[/cyan] {len(top100_lines)} конфигов с минимальной задержкой (от {lat_min:.0f} мс до {lat_max:.0f} мс)")
        console.print(f"[green][OK][/green] Top100 сохранён в: [bold]{top100_path}[/bold]")
    else:
        console.print("\n[yellow]Нет доступных конфигов для сохранения.[/yellow]")


if __name__ == "__main__":
    main()
