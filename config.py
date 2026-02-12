#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Модуль конфигурации - загрузка и хранение всех настроек из переменных окружения.
"""

import os
import urllib3
from dotenv import load_dotenv

load_dotenv()

# GitHub API для загрузки Xray-core
XRAY_RELEASES_API = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"


def _env(key: str, default: str) -> str:
    """Получить строковое значение переменной окружения."""
    return os.environ.get(key, default).strip()


def _env_int(key: str, default: int) -> int:
    """Получить целочисленное значение переменной окружения."""
    v = os.environ.get(key, "").strip()
    return int(v) if v else default


def _env_float(key: str, default: float) -> float:
    """Получить значение с плавающей точкой переменной окружения."""
    v = os.environ.get(key, "").strip()
    return float(v) if v else default


def _env_bool(key: str, default: bool) -> bool:
    """Получить булево значение переменной окружения."""
    v = os.environ.get(key, "").strip().lower()
    if not v:
        return default
    return v in ("1", "true", "yes", "on")


# Основные настройки
MODE = (_env("MODE", "single").strip().lower() or "single")
LINKS_FILE = _env("LINKS_FILE", "links.txt")
DEFAULT_LIST_URL = _env("DEFAULT_LIST_URL", "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/cidr")
OUTPUT_FILE = _env("OUTPUT_FILE", "available.txt")
# Добавлять к имени файла дату и источник (OUTPUT_FILE без даты при false)
OUTPUT_ADD_DATE = _env_bool("OUTPUT_ADD_DATE", False)

# Тестовые URL
TEST_URL = _env("TEST_URL", "http://www.google.com/generate_204")
TEST_URLS_STR = _env("TEST_URLS", "")
TEST_URLS_HTTPS_STR = _env("TEST_URLS_HTTPS", "")

# Парсинг списков URL
def _parse_url_list(url_str: str) -> list[str]:
    """Парсит список URL из строки (запятая или точка с запятой как разделитель)."""
    if not url_str:
        return []
    urls = []
    for sep in [",", ";"]:
        if sep in url_str:
            urls = [u.strip() for u in url_str.split(sep) if u.strip()]
            break
    if not urls:
        urls = [url_str.strip()] if url_str.strip() else []
    return urls

TEST_URLS = _parse_url_list(TEST_URLS_STR) if TEST_URLS_STR else []
TEST_URLS_HTTPS = _parse_url_list(TEST_URLS_HTTPS_STR) if TEST_URLS_HTTPS_STR else []

# Если TEST_URLS не задан, используем TEST_URL как единственный URL
if not TEST_URLS:
    TEST_URLS = [TEST_URL] if TEST_URL else []

# Параметры проверки
MIN_SUCCESSFUL_URLS = _env_int("MIN_SUCCESSFUL_URLS", 1)
REQUIRE_HTTPS = _env_bool("REQUIRE_HTTPS", False)

# URL, используемый клиентами (SagerNet, sing-box и др.) для проверки - по умолчанию gstatic
_CLIENT_TEST_HTTPS = "https://www.gstatic.com/generate_204"
if REQUIRE_HTTPS and not TEST_URLS_HTTPS:
    TEST_URLS_HTTPS = [_CLIENT_TEST_HTTPS]
REQUESTS_PER_URL = _env_int("REQUESTS_PER_URL", 1)
MIN_SUCCESSFUL_REQUESTS = _env_int("MIN_SUCCESSFUL_REQUESTS", 1)
REQUEST_DELAY = _env_float("REQUEST_DELAY", 0.5)

# Таймауты
CONNECT_TIMEOUT = _env_int("CONNECT_TIMEOUT", 8)
CONNECT_TIMEOUT_SLOW = _env_int("CONNECT_TIMEOUT_SLOW", 15)
USE_ADAPTIVE_TIMEOUT = _env_bool("USE_ADAPTIVE_TIMEOUT", False)

# Повторные попытки
MAX_RETRIES = _env_int("MAX_RETRIES", 1)
RETRY_DELAY_BASE = _env_float("RETRY_DELAY_BASE", 1.0)
RETRY_DELAY_MULTIPLIER = _env_float("RETRY_DELAY_MULTIPLIER", 2.0)

# Проверка ответов
MAX_RESPONSE_TIME = _env_float("MAX_RESPONSE_TIME", 0)
MIN_RESPONSE_SIZE = _env_int("MIN_RESPONSE_SIZE", 0)
VERIFY_HTTPS_SSL = _env_bool("VERIFY_HTTPS_SSL", False)

if not VERIFY_HTTPS_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Геолокация
CHECK_GEOLOCATION = _env_bool("CHECK_GEOLOCATION", False)
GEOLOCATION_SERVICE = _env("GEOLOCATION_SERVICE", "http://httpbin.org/ip")
ALLOWED_COUNTRIES_STR = _env("ALLOWED_COUNTRIES", "")
ALLOWED_COUNTRIES = [c.strip().upper() for c in ALLOWED_COUNTRIES_STR.split(",") if c.strip()] if ALLOWED_COUNTRIES_STR else []

# Проверка стабильности
STABILITY_CHECKS = _env_int("STABILITY_CHECKS", 1)
STABILITY_CHECK_DELAY = _env_float("STABILITY_CHECK_DELAY", 2.0)

# Строгий режим
STRICT_MODE = _env_bool("STRICT_MODE", False)
STRICT_MODE_REQUIRE_ALL = _env_bool("STRICT_MODE_REQUIRE_ALL", True)

# Строгий режим проверки (STRONG STYLE)
STRONG_STYLE_TEST = _env_bool("STRONG_STYLE_TEST", False)
STRONG_STYLE_TIMEOUT = _env_int("STRONG_STYLE_TIMEOUT", 30)
STRONG_MAX_RESPONSE_TIME = _env_int("STRONG_MAX_RESPONSE_TIME", 5)
STRONG_DOUBLE_CHECK = _env_bool("STRONG_DOUBLE_CHECK", True)

# Производительность
MAX_WORKERS = _env_int("MAX_WORKERS", 120)
BASE_PORT = _env_int("BASE_PORT", 20000)

# Настройки Xray
XRAY_STARTUP_WAIT = _env_float("XRAY_STARTUP_WAIT", 1.8)
XRAY_STARTUP_POLL_INTERVAL = _env_float("XRAY_STARTUP_POLL_INTERVAL", 0.2)
XRAY_CMD = _env("XRAY_PATH", "") or "xray"
XRAY_DIR_NAME = _env("XRAY_DIR_NAME", "xray_dist")

# Отладка
DEBUG_FIRST_FAIL = _env_bool("DEBUG_FIRST_FAIL", True)

# Логирование
LOG_LEVEL = _env("LOG_LEVEL", "INFO").upper()
LOG_FILE = _env("LOG_FILE", "")
LOG_MAX_SIZE = _env_int("LOG_MAX_SIZE", 10 * 1024 * 1024)  # 10MB
LOG_BACKUP_COUNT = _env_int("LOG_BACKUP_COUNT", 5)
LOG_RESPONSE_TIME = _env_bool("LOG_RESPONSE_TIME", False)

# Метрики
LOG_METRICS = _env_bool("LOG_METRICS", False)
METRICS_FILE = _env("METRICS_FILE", "metrics.json")
MIN_AVG_RESPONSE_TIME = _env_float("MIN_AVG_RESPONSE_TIME", 0)

# Дополнительные проверки
TEST_POST_REQUESTS = _env_bool("TEST_POST_REQUESTS", False)

# Кэширование
ENABLE_CACHE = _env_bool("ENABLE_CACHE", False)
CACHE_TTL = _env_int("CACHE_TTL", 3600)  # 1 час
CACHE_FILE = _env("CACHE_FILE", ".checker_cache.json")

# Экспорт
EXPORT_FORMAT = _env("EXPORT_FORMAT", "txt").lower()  # txt, json, csv, html, all
EXPORT_DIR = _env("EXPORT_DIR", "./exports")
