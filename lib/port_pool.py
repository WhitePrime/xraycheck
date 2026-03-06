#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Модуль управления пулом портов для SOCKS прокси.
"""

import logging
import threading

from .config import BASE_PORT, MAX_WORKERS

_logger = logging.getLogger(__name__)
_port_lock = threading.Lock()

# Ограничиваем пул, чтобы не выходить за пределы 65535.
_max_port = BASE_PORT + MAX_WORKERS - 1
if _max_port > 65535:
    _effective_workers = max(0, 65535 - BASE_PORT + 1)
    if _effective_workers <= 0:
        _effective_workers = 0
        _port_pool: list[int] = []
        _logger.warning(
            "Конфигурация портов некорректна: BASE_PORT=%s, MAX_WORKERS=%s выходит за диапазон портов. Пул пуст.",
            BASE_PORT,
            MAX_WORKERS,
        )
    else:
        _logger.warning(
            "MAX_WORKERS=%s слишком велик для BASE_PORT=%s, ограничиваем пул до %s воркеров.",
            MAX_WORKERS,
            BASE_PORT,
            _effective_workers,
        )
        _port_pool = list(range(BASE_PORT, BASE_PORT + _effective_workers))
else:
    _port_pool = list(range(BASE_PORT, BASE_PORT + MAX_WORKERS))


def take_port() -> int | None:
    """Берет порт из пула."""
    with _port_lock:
        if not _port_pool:
            return None
        return _port_pool.pop()


def return_port(port: int) -> None:
    """Возвращает порт в пул."""
    with _port_lock:
        _port_pool.append(port)
