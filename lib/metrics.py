#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Модуль метрик и статистики производительности.
"""

import statistics
from collections import defaultdict

from rich.console import Console
from rich.table import Table

console = Console()


def calculate_performance_metrics(results: list, all_metrics: dict, elapsed_time: float) -> dict:
    """Вычисляет метрики производительности."""
    metrics = {
        'total_keys': len(results),
        'checked_keys': len(results),
        'available_keys': 0,
        'failed_keys': 0,
        'avg_response_time': 0.0,
        'min_response_time': 0.0,
        'max_response_time': 0.0,
        'median_response_time': 0.0,
        'total_time': elapsed_time,
        'keys_per_second': 0.0,
        'error_distribution': defaultdict(int)
    }
    
    response_times = []
    for result in results:
        if isinstance(result, dict):
            if result.get('available', False):
                metrics['available_keys'] += 1
            else:
                metrics['failed_keys'] += 1
            
            if result.get('response_times'):
                response_times.extend(result['response_times'])
            
            if result.get('error'):
                error_type = type(result['error']).__name__
                metrics['error_distribution'][error_type] += 1
        elif isinstance(result, str):
            metrics['available_keys'] += 1
    
    # Если failed_keys не был подсчитан в цикле, вычисляем его
    if metrics['failed_keys'] == 0:
        metrics['failed_keys'] = metrics['total_keys'] - metrics['available_keys']
    
    if response_times:
        try:
            metrics['avg_response_time'] = statistics.mean(response_times)
            metrics['min_response_time'] = min(response_times)
            metrics['max_response_time'] = max(response_times)
            metrics['median_response_time'] = statistics.median(response_times)
        except (statistics.StatisticsError, ValueError):
            pass
    
    if elapsed_time > 0:
        metrics['keys_per_second'] = metrics['checked_keys'] / elapsed_time
    
    return metrics


def print_statistics_table(metrics: dict):
    """Выводит таблицу со статистикой."""
    table = Table(title="[bold green]Результаты проверки[/bold green]")
    table.add_column("Метрика", style="cyan", width=25)
    table.add_column("Значение", style="magenta", justify="right", width=20)
    
    success_rate = (metrics['available_keys'] / metrics['total_keys'] * 100) if metrics['total_keys'] > 0 else 0
    
    table.add_row("Всего ключей", f"{metrics['total_keys']:,}".replace(',', ' '))
    table.add_row("Рабочих", f"[green]{metrics['available_keys']:,}[/green]".replace(',', ' '))
    table.add_row("Не рабочих", f"[red]{metrics['failed_keys']:,}[/red]".replace(',', ' '))
    table.add_row("Успешность", f"{success_rate:.1f}%")
    if metrics['avg_response_time'] > 0:
        table.add_row("Среднее время ответа", f"{metrics['avg_response_time']:.2f} с")
        table.add_row("Мин. время ответа", f"{metrics['min_response_time']:.2f} с")
        table.add_row("Макс. время ответа", f"{metrics['max_response_time']:.2f} с")
        table.add_row("Медианное время", f"{metrics['median_response_time']:.2f} с")
    table.add_row("Время проверки", f"{metrics['total_time']:.1f} с")
    table.add_row("Скорость", f"{metrics['keys_per_second']:.2f} ключ/с")
    
    console.print(table)
