#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Модуль конфигурации - загрузка и хранение всех настроек из переменных окружения.
"""

import os
import urllib3
from dotenv import load_dotenv

# Загружаем .env из корня проекта (текущая рабочая директория при запуске vless_checker.py)
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
OUTPUT_FILE = _env("OUTPUT_FILE", "available")
# Директория для сохранения результатов проверки (txt, top100)
OUTPUT_DIR = _env("OUTPUT_DIR", "configs")
# Добавлять к имени файла дату и источник (OUTPUT_FILE без даты при false)
OUTPUT_ADD_DATE = _env_bool("OUTPUT_ADD_DATE", False)
# Файл с неактивными ключами (в OUTPUT_DIR): при старте ключи из него отсеиваются, после проверки нерабочие дополняют его с дедупликацией
NOTWORKERS_FILE = os.path.join(OUTPUT_DIR, "notworkers")
# Обновлять notworkers по результатам проверки (false = только читать для фильтра, не записывать)
NOTWORKERS_UPDATE_ENABLED = _env_bool("NOTWORKERS_UPDATE_ENABLED", True)

# Текст комментария для strip_vpn_comments.py (добавляется после флага страны к проверенным конфигам в workflow)
AUTO_COMMENT = _env("AUTO_COMMENT", " verified · XRayCheck")

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
# Максимальная задержка (мс): серверы с задержкой выше не попадают в available / white-list_available
MAX_LATENCY_MS = _env_int("MAX_LATENCY_MS", 3000)

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

# Строгий режим проверки (STRONG STYLE), как в мобильных клиентах
STRONG_STYLE_TEST = _env_bool("STRONG_STYLE_TEST", False)
STRONG_STYLE_TIMEOUT = _env_int("STRONG_STYLE_TIMEOUT", 12)
STRONG_MAX_RESPONSE_TIME = _env_int("STRONG_MAX_RESPONSE_TIME", 3)
STRONG_DOUBLE_CHECK = _env_bool("STRONG_DOUBLE_CHECK", True)
# Сколько подряд успешных запросов к gstatic/generate_204 требуется (3 = строже, меньше ложных «доступных»)
STRONG_ATTEMPTS = _env_int("STRONG_ATTEMPTS", 3)

# Производительность
MAX_WORKERS = _env_int("MAX_WORKERS", 120)
BASE_PORT = _env_int("BASE_PORT", 20000)

# Настройки Xray
XRAY_STARTUP_WAIT = _env_float("XRAY_STARTUP_WAIT", 1.8)
XRAY_STARTUP_POLL_INTERVAL = _env_float("XRAY_STARTUP_POLL_INTERVAL", 0.2)
# Сколько секунд ждать открытия SOCKS-порта после запуска процесса (как HYSTERIA_PORT_WAIT для Hysteria)
XRAY_PORT_WAIT = _env_float("XRAY_PORT_WAIT", 10)
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

# Speedtest (второй уровень, скрипт speedtest_checker.py)
SPEED_TEST_ENABLED = _env_bool("SPEED_TEST_ENABLED", False)
SPEED_TEST_TIMEOUT = _env_float("SPEED_TEST_TIMEOUT", 5.0)  # макс. секунд на конфиг (фаза задержки)
SPEED_TEST_MODE = _env("SPEED_TEST_MODE", "latency").strip().lower()  # latency | quick | full
SPEED_TEST_METRIC = _env("SPEED_TEST_METRIC", "latency").strip().lower()  # latency | throughput | hybrid
SPEED_TEST_OUTPUT = _env("SPEED_TEST_OUTPUT", "separate_file").strip().lower()
SPEED_TEST_REQUESTS = _env_int("SPEED_TEST_REQUESTS", 5)  # число запросов для latency
SPEED_TEST_URL = _env("SPEED_TEST_URL", "https://www.gstatic.com/generate_204")
SPEED_TEST_WORKERS = _env_int("SPEED_TEST_WORKERS", MAX_WORKERS)
# Загрузка файла для quick (250KB) / full (1MB) - скорость в Mbps
SPEED_TEST_DOWNLOAD_TIMEOUT = _env_int("SPEED_TEST_DOWNLOAD_TIMEOUT", 30)  # макс. секунд на загрузку
SPEED_TEST_DOWNLOAD_URL_SMALL = _env("SPEED_TEST_DOWNLOAD_URL_SMALL", "https://speed.cloudflare.com/__down?bytes=250000")
SPEED_TEST_DOWNLOAD_URL_MEDIUM = _env("SPEED_TEST_DOWNLOAD_URL_MEDIUM", "https://speed.cloudflare.com/__down?bytes=1000000")
MIN_SPEED_THRESHOLD_MBPS = _env_float("MIN_SPEED_THRESHOLD_MBPS", 2.5)  # мин. скорость Mbps для отсева (0 = не фильтровать)
SPEED_TEST_DEBUG = _env_bool("SPEED_TEST_DEBUG", False)  # выводить причину сбоя по каждому ключу
