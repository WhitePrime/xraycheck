#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Модуль настройки логирования.
"""

import logging
import os
import sys
from typing import Optional

from .config import LOG_LEVEL, LOG_FILE, LOG_MAX_SIZE, LOG_BACKUP_COUNT

# Глобальный флаг для отладки первого ключа (не влияет на уровень логирования)
_debug_first_key = False

logger = logging.getLogger(__name__)


def setup_logging(debug: bool = False, log_file: Optional[str] = None):
    """Настраивает систему логирования."""
    global _debug_first_key
    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
    }
    # Уровень логирования определяется только из LOG_LEVEL
    level = level_map.get(LOG_LEVEL, logging.INFO)
    _debug_first_key = debug and LOG_LEVEL == "DEBUG"  # Только если уровень DEBUG

    handlers = [logging.StreamHandler(sys.stdout)]

    # В GitHub Actions логирование должно идти только в stdout/stderr,
    # чтобы не создавать отдельные файлы логов прямо в рабочей копии репозитория.
    log_path = log_file or LOG_FILE
    if os.environ.get("GITHUB_ACTIONS", "").strip().lower() in ("true", "1", "yes", "on"):
        log_path = ""

    if log_path:
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler(
            log_path, maxBytes=LOG_MAX_SIZE, backupCount=LOG_BACKUP_COUNT, encoding='utf-8'
        )
        handlers.append(file_handler)

    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=handlers,
        force=True
    )


def should_debug(debug_flag: bool) -> bool:
    """Проверяет, нужно ли выводить отладочную информацию."""
    return debug_flag and _debug_first_key
