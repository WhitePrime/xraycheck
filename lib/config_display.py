#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Модуль отображения конфигурации.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .config import (
    BASE_PORT,
    CHECK_GEOLOCATION,
    CONNECT_TIMEOUT,
    CONNECT_TIMEOUT_SLOW,
    ENABLE_CACHE,
    MAX_LATENCY_MS,
    MAX_RESPONSE_TIME,
    MAX_RETRIES,
    MAX_WORKERS,
    MIN_SUCCESSFUL_URLS,
    MODE,
    REQUESTS_PER_URL,
    STABILITY_CHECKS,
    STRICT_MODE,
    STRONG_ATTEMPTS,
    STRONG_MAX_RESPONSE_TIME,
    STRONG_STYLE_TEST,
    STRONG_STYLE_TIMEOUT,
    TEST_URL,
    TEST_URLS,
    TEST_URLS_HTTPS,
    USE_ADAPTIVE_TIMEOUT,
    XRAY_PORT_WAIT,
    XRAY_STARTUP_POLL_INTERVAL,
    XRAY_STARTUP_WAIT,
    _CLIENT_TEST_HTTPS,
)
from .parsing import get_output_path

console = Console()


def print_current_config(list_url: str) -> None:
    """Выводит текущие параметры в понятном формате перед стартом."""
    output_path = get_output_path(list_url)
    ports_end = BASE_PORT + MAX_WORKERS - 1
    if STRONG_STYLE_TEST:
        reqs = f"{STRONG_ATTEMPTS} запроса подряд" if STRONG_ATTEMPTS != 1 else "1 запрос"
        test_urls_display = f"Строгий режим: {_CLIENT_TEST_HTTPS} ({reqs})"
    elif TEST_URLS:
        test_urls_display = ", ".join(TEST_URLS[:3]) + ("..." if len(TEST_URLS) > 3 else "")
    else:
        test_urls_display = TEST_URL if TEST_URL else "не задан"

    config_table = Table(show_header=False, box=None, padding=(0, 1))
    config_table.add_row("[cyan]Режим[/cyan]", f"[bold]{MODE}[/bold]")
    if STRONG_STYLE_TEST:
        config_table.add_row("[cyan]Алгоритм[/cyan]", f"строгий ({STRONG_ATTEMPTS} запроса подряд)")
        config_table.add_row("[cyan]Таймаут запроса[/cyan]", f"{STRONG_STYLE_TIMEOUT} с (connect + read)")
        config_table.add_row("[cyan]Макс. время ответа[/cyan]", f"{STRONG_MAX_RESPONSE_TIME} с")
    list_display = "по ссылке" if (list_url.startswith("http://") or list_url.startswith("https://")) else list_url
    config_table.add_row("[cyan]Список ключей[/cyan]", list_display)
    config_table.add_row("[cyan]Файл результата[/cyan]", output_path)
    config_table.add_row("[cyan]URL проверки[/cyan]", test_urls_display)
    if TEST_URLS_HTTPS:
        config_table.add_row("[cyan]HTTPS URL[/cyan]", f"{len(TEST_URLS_HTTPS)} URL")
    config_table.add_row("[cyan]Таймаут запроса[/cyan]", f"{CONNECT_TIMEOUT} с" + (f" (медленные: {CONNECT_TIMEOUT_SLOW} с)" if USE_ADAPTIVE_TIMEOUT else ""))
    config_table.add_row("[cyan]Повторных попыток[/cyan]", str(MAX_RETRIES + 1))
    config_table.add_row("[cyan]Запросов на URL[/cyan]", str(REQUESTS_PER_URL))
    config_table.add_row("[cyan]Минимум успешных[/cyan]", f"{MIN_SUCCESSFUL_URLS} URL")
    if STABILITY_CHECKS > 1:
        config_table.add_row("[cyan]Проверок стабильности[/cyan]", str(STABILITY_CHECKS))
    if MAX_RESPONSE_TIME > 0:
        config_table.add_row("[cyan]Макс. время ответа[/cyan]", f"{MAX_RESPONSE_TIME} с")
    if CHECK_GEOLOCATION:
        config_table.add_row("[cyan]Проверка геолокации[/cyan]", "[green]включена[/green]")
    if STRICT_MODE:
        config_table.add_row("[cyan]Строгий режим[/cyan]", "[green]включен[/green]")
    config_table.add_row("[cyan]Потоков[/cyan]", str(MAX_WORKERS))
    config_table.add_row("[cyan]Порты SOCKS[/cyan]", f"{BASE_PORT}-{ports_end}")
    config_table.add_row(
        "[cyan]Ожидание xray[/cyan]",
        f"{XRAY_STARTUP_WAIT} с после запуска, порт SOCKS до {XRAY_PORT_WAIT} с (проверка каждые {XRAY_STARTUP_POLL_INTERVAL} с)",
    )
    if ENABLE_CACHE:
        config_table.add_row("[cyan]Кэширование[/cyan]", "[green]включено[/green]")
    config_table.add_row("[cyan]Макс. задержка в файл[/cyan]", f"{MAX_LATENCY_MS} мс (серверы с задержкой выше не записываются)")

    console.print(Panel(config_table, title="[bold cyan]Параметры проверки[/bold cyan]", border_style="cyan"))
    console.print()
