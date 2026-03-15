#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Модуль обработки сигналов прерывания (Ctrl+C).
"""

import atexit
import signal
import subprocess
import sys
import threading
from typing import TYPE_CHECKING

from rich.console import Console

if TYPE_CHECKING:
    from .xray_manager import kill_xray_process

console = Console()

# Глобальные переменные для обработки сигналов
_active_lock = threading.Lock()
active_processes: list[tuple[subprocess.Popen, int]] = []
interrupted = False
available_keys: list[str] = []
output_path_global: str = ""


def register_process(proc: subprocess.Popen, port: int) -> None:
    """Потокобезопасно регистрирует активный процесс xray."""
    with _active_lock:
        active_processes.append((proc, port))


def unregister_process(proc: subprocess.Popen, port: int) -> None:
    """Потокобезопасно удаляет процесс xray из списка активных."""
    with _active_lock:
        try:
            active_processes.remove((proc, port))
        except ValueError:
            # Уже удалён (например, другим потоком или при обработке сигнала)
            pass


def _snapshot_and_clear_active() -> list[tuple[subprocess.Popen, int]]:
    """Возвращает копию списка активных процессов и очищает его (под lock)."""
    with _active_lock:
        items = list(active_processes)
        active_processes.clear()
        return items


def signal_handler(signum, frame):
    """Обработчик сигналов прерывания."""
    global interrupted
    interrupted = True
    console.print("\n\n[bold yellow][!][/bold yellow] Получен сигнал прерывания. Завершение работы...")
    cleanup_processes()
    save_partial_results()
    sys.exit(0)


def cleanup_processes():
    """Корректно завершает все активные процессы xray."""
    # Импортируем здесь, чтобы избежать циклических зависимостей
    from .xray_manager import kill_xray_process
    from .port_pool import return_port

    items = _snapshot_and_clear_active()
    for proc, port in items:
        kill_xray_process(proc)
        return_port(port)


def save_partial_results():
    """Сохраняет частичные результаты при прерывании."""
    global available_keys, output_path_global
    if available_keys and output_path_global:
        partial_path = output_path_global.replace('.txt', '_partial.txt')
        try:
            with open(partial_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(available_keys))
            console.print(f"[green]✓[/green] Промежуточные результаты сохранены в: {partial_path}")
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"Ошибка сохранения промежуточных результатов: {e}")


# Регистрация обработчиков сигналов
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)
atexit.register(cleanup_processes)
