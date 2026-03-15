#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Speedtest одного прокси-ключа: задержка (RTT) и/или скорость загрузки (Mbps).
Режимы: latency - только задержка; quick - задержка + 250KB; full - задержка + 1MB.
Используется отдельным скриптом speedtest_checker.py для уже проверенных конфигов.
"""

import json
import logging
import os
import socket
import tempfile
import time
from typing import Optional

import requests

from .config import (
    SPEED_TEST_DEBUG,
    SPEED_TEST_DOWNLOAD_TIMEOUT,
    SPEED_TEST_DOWNLOAD_URL_MEDIUM,
    SPEED_TEST_DOWNLOAD_URL_SMALL,
    SPEED_TEST_METRIC,
    SPEED_TEST_MODE,
    SPEED_TEST_REQUESTS,
    SPEED_TEST_TIMEOUT,
    SPEED_TEST_URL,
    VERIFY_HTTPS_SSL,
    XRAY_PORT_WAIT,
    XRAY_STARTUP_POLL_INTERVAL,
    XRAY_STARTUP_WAIT,
)
from .parsing import parse_proxy_url
from .port_pool import return_port, take_port
from .signals import register_process, unregister_process
from .utils import check_response_valid, make_request
from .xray_manager import build_xray_config, kill_xray_process, run_xray

logger = logging.getLogger(__name__)


def _wait_for_port(host: str, port: int, max_wait: float, poll_interval: float = 0.05) -> bool:
    """Ждёт, пока порт станет доступен для подключения (xray поднял SOCKS)."""
    deadline = time.perf_counter() + max_wait
    while time.perf_counter() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.3):
                return True
        except (socket.error, socket.gaierror, OSError):
            time.sleep(poll_interval)
    return False


# Hysteria: проверка доступности по TCP (как в checker)
def _hysteria_latency(address: str, port: int, timeout: float) -> Optional[float]:
    try:
        start = time.perf_counter()
        with socket.create_connection((address, port), timeout=timeout):
            return (time.perf_counter() - start) * 1000.0
    except (socket.error, socket.gaierror, OSError):
        return None


def _test_download_speed(
    proxies: dict,
    url: str,
    timeout_sec: int,
) -> Optional[float]:
    """
    Тест скорости загрузки через прокси (stream).
    Возвращает среднюю скорость в Mbps или None.
    """
    try:
        verify = VERIFY_HTTPS_SSL if url.lower().startswith("https://") else True
        start_time = time.perf_counter()
        r = requests.get(
            url,
            proxies=proxies,
            timeout=(5, timeout_sec),
            stream=True,
            allow_redirects=False,
            verify=verify,
        )
        if r.status_code != 200:
            return None
        downloaded = 0
        chunk_size = 8192
        for chunk in r.iter_content(chunk_size=chunk_size):
            if chunk:
                downloaded += len(chunk)
            if time.perf_counter() - start_time > timeout_sec:
                break
        elapsed = time.perf_counter() - start_time
        if elapsed < 0.3:
            return None
        speed_mbps = (downloaded * 8) / (elapsed * 1_000_000)
        return round(speed_mbps, 2)
    except requests.RequestException:
        return None


def speed_test_key(
    proxy_line: str,
    timeout: float,
    metric: str,
    requests_count: int,
    test_url: str,
    mode: str = "latency",
    download_timeout: int = 30,
    download_url_small: str = "",
    download_url_medium: str = "",
) -> Optional[tuple[str, float]]:
    """
    Speedtest одного ключа.
    mode=latency: только задержка (score = latency_ms, меньше = лучше).
    mode=quick: задержка + загрузка 250KB (score = speed_mbps, больше = лучше).
    mode=full: задержка + загрузка 1MB (score = speed_mbps, больше = лучше).
    Возвращает (строка_ключа, score) или None при ошибке.
    """
    parsed = parse_proxy_url(proxy_line)
    if not parsed:
        if SPEED_TEST_DEBUG:
            logger.info("speed_test_key: parse failed")
        return None

    if parsed.get("protocol") in ("hysteria", "hysteria2"):
        ok_latency = _hysteria_latency(parsed["address"], parsed["port"], min(timeout, 5.0))
        if ok_latency is not None:
            return (proxy_line, ok_latency)
        if SPEED_TEST_DEBUG:
            logger.info("speed_test_key: hysteria latency failed")
        return None

    port = take_port()
    if port is None:
        if SPEED_TEST_DEBUG:
            logger.info("speed_test_key: no free port")
        return None

    proc = None
    config = build_xray_config(parsed, port)
    fd, config_path = tempfile.mkstemp(suffix=".json", prefix="xray_st_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        return_port(port)
        return None

    try:
        proc = run_xray(config_path, stderr_pipe=False)
        register_process(proc, port)
        waited = 0.0
        while waited < XRAY_STARTUP_WAIT:
            if proc.poll() is not None:
                break
            time.sleep(XRAY_STARTUP_POLL_INTERVAL)
            waited += XRAY_STARTUP_POLL_INTERVAL
        if proc.poll() is not None:
            if SPEED_TEST_DEBUG:
                logger.info("speed_test_key: xray process exited early")
            return None

        port_wait = min(XRAY_PORT_WAIT, timeout + 5)
        if not _wait_for_port("127.0.0.1", port, max_wait=port_wait):
            if SPEED_TEST_DEBUG:
                logger.info("speed_test_key: port wait timeout")
            return None

        proxies = {
            "http": f"socks5h://127.0.0.1:{port}",
            "https": f"socks5h://127.0.0.1:{port}",
        }
        deadline = time.perf_counter() + timeout
        response_times: list[float] = []
        per_request_timeout = max(1.0, (timeout - 0.2) / max(1, requests_count))

        last_resp_status = None
        last_err = None
        for _ in range(requests_count):
            if time.perf_counter() >= deadline:
                break
            connect_t = min(5, max(1.0, per_request_timeout * 0.5))
            read_t = min(15, max(3.0, per_request_timeout * 0.6))
            resp, elapsed, err = make_request(test_url, proxies, (connect_t, read_t))
            if err:
                last_err = err
            if resp:
                last_resp_status = resp.status_code
            if resp and not err and check_response_valid(resp, 0, test_url):
                response_times.append(elapsed * 1000.0)
        if not response_times:
            if SPEED_TEST_DEBUG:
                if last_err:
                    logger.info("speed_test_key: HTTP request failed: %s", last_err)
                elif last_resp_status is not None:
                    logger.info("speed_test_key: invalid response status=%s (expected 200/204)", last_resp_status)
                else:
                    logger.info("speed_test_key: no valid HTTP response (timeout or invalid)")
            return None
        avg_latency_ms = sum(response_times) / len(response_times)

        if mode == "quick" and download_url_small:
            speed_mbps = _test_download_speed(proxies, download_url_small, min(10, download_timeout))
            if speed_mbps is not None:
                return (proxy_line, speed_mbps)
            return None
        if mode == "full" and download_url_medium:
            speed_mbps = _test_download_speed(proxies, download_url_medium, download_timeout)
            if speed_mbps is not None:
                return (proxy_line, speed_mbps)
            return None

        if mode == "latency" or not (download_url_small or download_url_medium):
            if metric == "throughput":
                return (proxy_line, 100000.0 / avg_latency_ms if avg_latency_ms > 0 else 0)
            return (proxy_line, avg_latency_ms)
        return (proxy_line, avg_latency_ms)
    except Exception as e:
        logger.debug("speed_test_key %s", e)
        if SPEED_TEST_DEBUG:
            logger.info("speed_test_key: exception %s", e)
        return None
    finally:
        if proc is not None:
            unregister_process(proc, port)
            kill_xray_process(proc, drain_stderr=False)
        try:
            os.unlink(config_path)
        except FileNotFoundError:
            pass
        return_port(port)
