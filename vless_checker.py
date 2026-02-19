#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Проверка прокси-ключей (end-to-end).
Поддерживает протоколы: VLESS, VMess, Trojan, Shadowsocks, Hysteria, Hysteria2.
Загружает список по URL; для каждого ключа: поднимает локальный прокси через xray
(или проверка доступности для Hysteria/Hysteria2), делает HTTP-запрос через прокси
к тестовому URL; по ответу решает «жив»/«мёртв». Рабочие ключи сохраняются в файл.
"""

import json
import os
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

from cache import load_cache, save_cache
from checker import check_key_e2e
from config import (
    DEBUG_FIRST_FAIL,
    DEFAULT_LIST_URL,
    ENABLE_CACHE,
    EXPORT_FORMAT,
    LINKS_FILE,
    LOG_METRICS,
    LOG_RESPONSE_TIME,
    MAX_LATENCY_MS,
    MAX_WORKERS,
    METRICS_FILE,
    MODE,
)
from config_display import print_current_config
from export import export_to_csv, export_to_html, export_to_json
from metrics import calculate_performance_metrics, print_statistics_table
from parsing import decode_subscription_content, get_output_path, load_merged_keys, parse_proxy_lines, parse_proxy_url
from signals import available_keys, interrupted, output_path_global
from xray_manager import build_xray_config, ensure_xray

console = Console()


def main():
    global available_keys, output_path_global
    
    # Инициализация логирования
    from logger_config import setup_logging
    setup_logging(debug=False)
    
    args = [a for a in sys.argv[1:] if a.startswith("-")]
    urls_arg = [a for a in sys.argv[1:] if not a.startswith("-")]
    print_config = "--print-config" in args or "-p" in args

    def load_list(url_or_path: str) -> str:
        """Загружает список по URL или читает из локального файла."""
        if url_or_path.startswith("http://") or url_or_path.startswith("https://"):
            r = requests.get(url_or_path, timeout=15)
            r.raise_for_status()
            return r.text
        with open(url_or_path, encoding="utf-8") as f:
            return f.read()

    # Определяем источник ключей и загружаем список в зависимости от режима
    if MODE == "merge":
        list_url = "merged"
        script_dir = os.path.dirname(os.path.abspath(__file__))
        links_path = LINKS_FILE if os.path.isfile(LINKS_FILE) else os.path.join(script_dir, LINKS_FILE)
        if not os.path.isfile(links_path):
            console.print(f"[bold red]Ошибка:[/bold red] файл со ссылками не найден: {links_path}")
            sys.exit(1)
        try:
            _, keys = load_merged_keys(links_path)
        except (requests.RequestException, OSError) as e:
            console.print(f"[bold red]Ошибка загрузки списков:[/bold red] {e}")
            sys.exit(1)
    else:
        list_url = urls_arg[0] if urls_arg else DEFAULT_LIST_URL
        try:
            text = load_list(list_url)
        except (requests.RequestException, OSError) as e:
            console.print(f"[bold red]Ошибка загрузки списка:[/bold red] {e}")
            sys.exit(1)
        # Поддержка подписок в base64 (ссылки вроде nowmeow.pw/.../whitelist, gitverse.ru/.../whitelist.txt)
        text = decode_subscription_content(text)
        keys = parse_proxy_lines(text)

    output_path = get_output_path(list_url)

    if print_config:
        if not keys:
            console.print("[red]Нет ключей в списке.[/red]")
            sys.exit(1)
        from parsing import parse_proxy_url
        parsed = parse_proxy_url(keys[0][0])
        if not parsed:
            console.print("[red]Не удалось разобрать первый ключ.[/red]")
            sys.exit(1)
        config = build_xray_config(parsed, 10808)
        console.print(json.dumps(config, indent=2, ensure_ascii=False))
        console.print("\n[yellow]Сохраните в config.json и запустите:[/yellow] xray run -config config.json")
        sys.exit(0)

    print_current_config(list_url)

    console.print("[cyan]Проверка xray...[/cyan]")
    if not ensure_xray():
        console.print("[bold red]Ошибка: xray недоступен.[/bold red]")
        console.print("Установите Xray-core вручную и добавьте в PATH или задайте XRAY_PATH.")
        sys.exit(1)
    console.print("[green]✓[/green] xray готов.\n")

    if MODE == "merge":
        console.print(f"[cyan]Ключи объединены из {LINKS_FILE}.[/cyan]")
    else:
        console.print(f"[cyan]Загрузка списка:[/cyan] {list_url}")
    console.print(f"[bold]Найдено ключей:[/bold] {len(keys):,}".replace(',', ' '))
    if not keys:
        console.print("[yellow]Нет ключей для проверки.[/yellow]")
        sys.exit(0)

    # link -> полная строка (для сохранения в available.txt с метаданными)
    link_to_full: dict[str, str] = {link: full for link, full in keys}
    links_only = [link for link, _ in keys]
    total = len(links_only)

    available: list[tuple[str, float]] = []  # Список (отформатированная_строка, задержка_мс)
    available_keys = []  # Для глобального доступа в обработчике сигналов (список строк)
    all_metrics: dict[str, dict] = {}
    time_start = time.perf_counter()
    
    # Загрузка кэша
    cache = load_cache() if ENABLE_CACHE else None

    def format_key_with_metadata(link: str, metrics: Optional[dict]) -> tuple[str, float]:
        """
        Форматирует ключ с метаданными для сохранения.
        Возвращает (отформатированная_строка, задержка_в_мс).
        Задержка используется для сортировки (0 если нет данных).
        """
        full_line = link_to_full.get(link, link)
        
        # Вычисляем среднюю задержку в мс
        avg_latency_ms = 0.0
        if metrics and metrics.get("response_times"):
            avg_time_sec = sum(metrics["response_times"]) / len(metrics["response_times"])
            avg_latency_ms = avg_time_sec * 1000  # Конвертируем в миллисекунды
        
        # Если метаданные не нужны или нет метрик, возвращаем простую строку с префиксом задержки
        if not metrics or not LOG_RESPONSE_TIME:
            # Добавляем задержку в начало строки: [latency_ms] link
            formatted = f"[{int(avg_latency_ms)}ms] {full_line}"
            return (formatted, avg_latency_ms)
        
        metadata_lines = []
        metadata_lines.append(f"# Проверено: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        if metrics.get("response_times"):
            avg_time = sum(metrics["response_times"]) / len(metrics["response_times"])
            min_time = min(metrics["response_times"])
            max_time = max(metrics["response_times"])
            avg_ms = avg_time * 1000
            min_ms = min_time * 1000
            max_ms = max_time * 1000
            metadata_lines.append(f"# Задержка: мин={min_ms:.0f}мс, макс={max_ms:.0f}мс, среднее={avg_ms:.0f}мс")
        
        if metrics.get("geolocation"):
            geo = metrics["geolocation"]
            if "ip" in geo:
                metadata_lines.append(f"# IP: {geo['ip']}")
        
        if metrics.get("successful_urls") is not None:
            metadata_lines.append(f"# Успешных URL: {metrics['successful_urls']}/{metrics['successful_urls'] + metrics.get('failed_urls', 0)}")
        
        if metrics.get("successful_requests") is not None:
            metadata_lines.append(f"# Успешных запросов: {metrics['successful_requests']}/{metrics.get('total_requests', 0)}")
        
        # Формируем строку с метаданными и ссылкой
        formatted = "\n".join(metadata_lines) + "\n" + full_line
        return (formatted, avg_latency_ms)

    output_path_global = output_path
    
    # Первый ключ проверяем с выводом отладки при неудаче
    if DEBUG_FIRST_FAIL and links_only:
        link0 = links_only[0]
        _, ok0, metrics0 = check_key_e2e(link0, debug=True, cache=cache)
        all_metrics[link0] = metrics0
        if ok0:
            formatted, latency = format_key_with_metadata(link0, metrics0)
            if latency <= MAX_LATENCY_MS:
                available.append((formatted, latency))
                available_keys.append(link0)
                console.print(f"[green]✓[/green] [1/{total}] OK ({int(latency)}мс)")
            else:
                console.print(f"[yellow]✗[/yellow] [1/{total}] OK, но задержка {int(latency)}мс > {MAX_LATENCY_MS}мс (пропуск)")
        else:
            console.print(f"[red]✗[/red] [1/{total}] fail (см. логи выше)")
        links_only = links_only[1:]
        if not links_only:
            elapsed = time.perf_counter() - time_start
            save_results_and_exit(available, all_metrics, output_path, elapsed, total, cache)
            return
        done = 1
    else:
        done = 0

    # Прогресс-бар с rich
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("({task.completed}/{task.total})"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=False  # Не скрывать прогресс-бар после завершения
    ) as progress:
        task = progress.add_task(
            f"[cyan]Проверка ключей...[/cyan] [OK: 0, FAIL: 0]",
            total=len(links_only)
        )
        
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(check_key_e2e, link, debug=False, cache=cache): link for link in links_only}
            for future in as_completed(futures):
                if interrupted:
                    break
                done += 1
                try:
                    link, ok, metrics = future.result()
                    all_metrics[link] = metrics
                    if ok:
                        formatted, latency = format_key_with_metadata(link, metrics)
                        if latency <= MAX_LATENCY_MS:
                            available.append((formatted, latency))
                            available_keys.append(link)
                    
                    # Обновляем прогресс-бар одной строкой
                    ok_count = len(available)
                    fail_count = done - ok_count
                    avg_time_str = ""
                    if ok and LOG_RESPONSE_TIME and metrics.get("response_times"):
                        avg_time = sum(metrics["response_times"]) / len(metrics["response_times"])
                        avg_time_str = f", avg: {avg_time:.2f}с"
                    
                    progress.update(
                        task,
                        advance=1,
                        description=f"[cyan]Проверка ключей...[/cyan] [OK: {ok_count}, FAIL: {fail_count}{avg_time_str}]"
                    )
                except Exception as e:
                    from logger_config import logger
                    logger.error(f"Ошибка проверки ключа: {e}")
                    fail_count = done - len(available)
                    progress.update(
                        task,
                        advance=1,
                        description=f"[cyan]Проверка ключей...[/cyan] [OK: {len(available)}, FAIL: {fail_count}, ERROR: 1]"
                    )

    elapsed = time.perf_counter() - time_start
    save_results_and_exit(available, all_metrics, output_path, elapsed, total, cache)


def _create_top100_file(output_path: str, available_sorted: list[tuple[str, float]]) -> Optional[str]:
    """
    Создает файл с топ-100 конфигами (минимальная задержка).
    Возвращает путь к созданному файлу или None если недостаточно ключей.
    """
    if len(available_sorted) == 0:
        return None
    
    # Берем первые 100 элементов
    top100 = available_sorted[:100]
    
    # Формируем имя файла: исходное_имя + (top100).txt (без пробела перед скобкой)
    base_path = Path(output_path)
    base_name = base_path.stem  # Имя без расширения
    base_ext = base_path.suffix or ".txt"  # Расширение или .txt по умолчанию
    top100_name = f"{base_name}(top100){base_ext}"
    top100_path = base_path.parent / top100_name
    
    # Сохраняем top100 (с префиксом задержки для информации)
    top100_lines = [item[0] for item in top100]
    with open(top100_path, "w", encoding="utf-8") as f:
        f.write("\n".join(top100_lines))
    
    console.print(f"[cyan]Top100:[/cyan] {len(top100)} ключей с минимальной задержкой (от {top100[0][1]:.0f}мс до {top100[-1][1]:.0f}мс)")
    return str(top100_path)


def save_results_and_exit(available: list[tuple[str, float]], all_metrics: dict, output_path: str, elapsed: float, total: int, cache: Optional[dict] = None):
    """
    Сохраняет результаты и выводит статистику.
    available: список кортежей (отформатированная_строка, задержка_в_мс)
    """
    from logger_config import logger
    
    # Сохранение кэша
    if cache is not None and ENABLE_CACHE:
        save_cache(cache)
    
    # Сортировка по задержке (минимальная в начале)
    available_sorted = sorted(available, key=lambda x: x[1])
    
    # Сохранение результатов в текстовый файл (отсортированные)
    if available_sorted:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        # Извлекаем только строки (без задержки) для сохранения
        available_lines = [item[0] for item in available_sorted]
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(available_lines))
        console.print(f"\n[green]✓[/green] Результаты сохранены в: [bold]{output_path}[/bold] (отсортированы по задержке)")
        
        # Создание top100 файла
        top100_path = _create_top100_file(output_path, available_sorted)
        if top100_path:
            console.print(f"[green]✓[/green] Top100 сохранен в: [bold]{top100_path}[/bold]")
    else:
        console.print("\n[yellow]Нет доступных ключей для сохранения.[/yellow]")
    
    # Расчет метрик производительности
    # Создаем множество доступных ссылок для быстрой проверки
    available_links = set()
    for formatted_str, _ in available_sorted:
        # Если строка содержит метаданные (начинается с # или [latency_ms]), берем последнюю строку
        lines = formatted_str.strip().split('\n')
        if lines:
            # Ищем строку с протоколом (последняя непустая строка, которая начинается с протокола)
            for line in reversed(lines):
                line = line.strip()
                # Убираем префикс [latency_ms] если есть
                if line.startswith('[') and 'ms]' in line:
                    line = line.split(']', 1)[1].strip()
                # Извлекаем чистую ссылку (до первого пробела или конца строки)
                if line.startswith(('vless://', 'vmess://', 'trojan://', 'ss://', 'hysteria://', 'hysteria2://', 'hy2://')):
                    link = line.split()[0] if line.split() else line
                    available_links.add(link)
                    break
    
    results_for_metrics = []
    for link, metrics in all_metrics.items():
        results_for_metrics.append({
            'key': link,
            'available': link in available_links,
            'response_times': metrics.get('response_times', []),
            'avg_response_time': statistics.mean(metrics.get('response_times', [])) if metrics.get('response_times') else 0,
            'geolocation': metrics.get('geolocation'),
            'error': None
        })
    
    perf_metrics = calculate_performance_metrics(results_for_metrics, all_metrics, elapsed)
    print_statistics_table(perf_metrics)
    
    # Экспорт в различные форматы
    if EXPORT_FORMAT in ('json', 'all'):
        json_path = export_to_json(results_for_metrics, all_metrics, output_path)
        console.print(f"[green]✓[/green] JSON экспорт: {json_path}")
    
    if EXPORT_FORMAT in ('csv', 'all'):
        csv_path = export_to_csv(results_for_metrics, output_path)
        console.print(f"[green]✓[/green] CSV экспорт: {csv_path}")
    
    if EXPORT_FORMAT in ('html', 'all'):
        html_path = export_to_html(results_for_metrics, all_metrics, output_path)
        console.print(f"[green]✓[/green] HTML экспорт: {html_path}")
    
    # Сохранение метрик
    if LOG_METRICS and all_metrics:
        metrics_path = METRICS_FILE if os.path.dirname(METRICS_FILE) else os.path.join(os.path.dirname(output_path), METRICS_FILE)
        try:
            Path(metrics_path).parent.mkdir(parents=True, exist_ok=True)
            with open(metrics_path, "w", encoding="utf-8") as f:
                json.dump(all_metrics, f, indent=2, ensure_ascii=False)
            console.print(f"[green]✓[/green] Метрики сохранены в: {metrics_path}")
        except Exception as e:
            logger.error(f"Ошибка сохранения метрик: {e}")


if __name__ == "__main__":
    main()
