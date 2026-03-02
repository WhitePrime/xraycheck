#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Модуль кэширования результатов проверки.
"""

import hashlib
import json
import time
from pathlib import Path
from typing import Optional

from .config import ENABLE_CACHE, CACHE_FILE, CACHE_TTL


def get_key_hash(vless_line: str) -> str:
    """Вычисляет хеш ключа для использования в кэше."""
    return hashlib.sha256(vless_line.encode()).hexdigest()[:16]


def load_cache() -> dict:
    """Загружает кэш из файла."""
    if not ENABLE_CACHE or not CACHE_FILE:
        return {}
    cache_path = Path(CACHE_FILE)
    if not cache_path.exists():
        return {}
    try:
        with open(cache_path, 'r', encoding='utf-8') as f:
            cache = json.load(f)
        current_time = time.time()
        return {
            k: v for k, v in cache.items()
            if current_time - v.get('timestamp', 0) < CACHE_TTL
        }
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"Ошибка загрузки кэша: {e}")
        return {}


def save_cache(cache: dict):
    """Сохраняет кэш в файл."""
    if not ENABLE_CACHE or not CACHE_FILE:
        return
    try:
        cache_path = Path(CACHE_FILE)
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_path, 'w', encoding='utf-8') as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"Ошибка сохранения кэша: {e}")


def check_cache(key_hash: str, cache: dict) -> Optional[bool]:
    """Проверяет кэш и возвращает результат или None."""
    if not ENABLE_CACHE or key_hash not in cache:
        return None
    entry = cache[key_hash]
    if time.time() - entry.get('timestamp', 0) < CACHE_TTL:
        return entry.get('result')
    return None
