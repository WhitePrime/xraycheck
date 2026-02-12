#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Модуль обработки сигналов прерывания (Ctrl+C).
"""

import atexit
import signal
import subprocess
import sys
from typing import TYPE_CHECKING

from rich.console import Console

if TYPE_CHECKING:
    from xray_manager import kill_xray_process

console = Console()

# Глобальные переменные для обработки сигналов
active_processes: list[tuple[subprocess.Popen, int]] = []
interrupted = False
available_keys: list[str] = []
output_path_global: str = ""


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
    from xray_manager import kill_xray_process
    from port_pool import return_port
    
    for proc, port in active_processes:
        kill_xray_process(proc)
        return_port(port)
    active_processes.clear()


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
