#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Модуль управления пулом портов для SOCKS прокси.
"""

import threading

from config import BASE_PORT, MAX_WORKERS

# Пул портов для SOCKS (по одному на поток)
_port_lock = threading.Lock()
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
