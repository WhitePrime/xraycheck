#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Модуль утилит: HTTP запросы, валидация ответов, геолокация.
"""

import time
from typing import Optional

import requests

from .config import (
    CHECK_GEOLOCATION,
    CONNECT_TIMEOUT,
    GEOLOCATION_SERVICE,
    MAX_RESPONSE_TIME,
    MIN_RESPONSE_SIZE,
    VERIFY_HTTPS_SSL,
)


def _is_connection_error(exc: BaseException) -> bool:
    """Проверяет, что ошибка связана с обрывом/отказом соединения (часто временная)."""
    s = str(exc).lower()
    if "connection aborted" in s or "connection reset" in s:
        return True
    if getattr(exc, "__cause__", None):
        c = exc.__cause__
        if type(c).__name__ in ("ConnectionResetError", "ConnectionAbortedError", "ConnectionRefusedError"):
            return True
    return False


def _get_geolocation(proxies: dict, service_url: str) -> Optional[dict]:
    """Получает геолокацию через прокси. Возвращает словарь с информацией или None."""
    try:
        r = requests.get(service_url, proxies=proxies, timeout=CONNECT_TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            if "origin" in data:
                ip = data["origin"].split(",")[0].strip()
                return {"ip": ip}
            return data
    except Exception:
        pass
    return None


def _check_geolocation_allowed(geolocation: Optional[dict], allowed_countries: list[str]) -> bool:
    """Проверяет, разрешена ли геолокация. Если allowed_countries пуст, разрешены все."""
    if not allowed_countries:
        return True
    if not geolocation:
        return False
    return "ip" in geolocation


def make_request(
    url: str,
    proxies: dict,
    timeout: float | tuple[float, float],
    method: str = "GET",
    post_data: Optional[dict] = None,
) -> tuple[Optional[requests.Response], float, Optional[Exception]]:
    """Выполняет HTTP-запрос и возвращает (response, время_ответа, ошибка).
    timeout: число (общий таймаут) или (connect_timeout, read_timeout)."""
    start_time = time.perf_counter()
    verify_ssl = VERIFY_HTTPS_SSL if url.lower().startswith("https://") else True
    try:
        if method == "POST" and post_data:
            r = requests.post(
                url, proxies=proxies, timeout=timeout, json=post_data,
                allow_redirects=False, verify=verify_ssl,
            )
        else:
            r = requests.get(
                url, proxies=proxies, timeout=timeout,
                allow_redirects=False, verify=verify_ssl,
            )
        elapsed = time.perf_counter() - start_time
        return (r, elapsed, None)
    except requests.RequestException as e:
        elapsed = time.perf_counter() - start_time
        return (None, elapsed, e)


def check_response_valid(
    response: requests.Response, min_size: int = 0, url: str = ""
) -> bool:
    """Проверяет валидность ответа: статус-код и размер.
    Для URL вида generate_204 (как в клиентах SagerNet и др.) требуется код 204."""
    if not response:
        return False
    if "generate_204" in (url or ""):
        # Через прокси сервер может вернуть 200 или 204; для speedtest/проверки достаточно любого успешного ответа
        if response.status_code not in (200, 204):
            return False
        if len(response.content) > 64:
            return False
    elif not (200 <= response.status_code < 400):
        return False
    if min_size > 0:
        content_length = len(response.content)
        if content_length < min_size:
            return False
    return True


def get_geolocation(proxies: dict) -> Optional[dict]:
    """Получает геолокацию через прокси (если включено)."""
    if not CHECK_GEOLOCATION:
        return None
    return _get_geolocation(proxies, GEOLOCATION_SERVICE)


def check_geolocation_allowed(geolocation: Optional[dict], allowed_countries: list[str]) -> bool:
    """Проверяет, разрешена ли геолокация."""
    return _check_geolocation_allowed(geolocation, allowed_countries)


def is_connection_error(exc: BaseException) -> bool:
    """Проверяет, является ли ошибка ошибкой соединения."""
    return _is_connection_error(exc)
