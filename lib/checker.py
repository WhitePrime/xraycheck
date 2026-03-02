#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Модуль проверки прокси-ключей - основная логика проверки.
Поддерживает протоколы: VLESS, VMess, Trojan, Shadowsocks, Hysteria, Hysteria2.
"""

import json
import logging
import os
import socket
import tempfile
import time
from typing import Optional

from .cache import check_cache, get_key_hash
from .config import (
    ALLOWED_COUNTRIES,
    CHECK_GEOLOCATION,
    CONNECT_TIMEOUT,
    CONNECT_TIMEOUT_SLOW,
    ENABLE_CACHE,
    MAX_RESPONSE_TIME,
    MAX_RETRIES,
    MIN_AVG_RESPONSE_TIME,
    MIN_RESPONSE_SIZE,
    MIN_SUCCESSFUL_REQUESTS,
    MIN_SUCCESSFUL_URLS,
    REQUEST_DELAY,
    REQUESTS_PER_URL,
    REQUIRE_HTTPS,
    RETRY_DELAY_BASE,
    RETRY_DELAY_MULTIPLIER,
    STABILITY_CHECK_DELAY,
    STABILITY_CHECKS,
    STRICT_MODE,
    STRICT_MODE_REQUIRE_ALL,
    STRONG_ATTEMPTS,
    STRONG_MAX_RESPONSE_TIME,
    STRONG_STYLE_TEST,
    STRONG_STYLE_TIMEOUT,
    TEST_POST_REQUESTS,
    TEST_URL,
    TEST_URLS,
    TEST_URLS_HTTPS,
    USE_ADAPTIVE_TIMEOUT,
    XRAY_STARTUP_POLL_INTERVAL,
    XRAY_STARTUP_WAIT,
    XRAY_PORT_WAIT,
    _CLIENT_TEST_HTTPS,
)
from .logger_config import should_debug as should_debug_func

logger = logging.getLogger(__name__)
from .parsing import parse_proxy_url, parse_vless_url
from .port_pool import return_port, take_port


def _wait_for_port(host: str, port: int, max_wait: float, poll_interval: float = 0.1) -> bool:
    """Ждёт, пока SOCKS-порт на localhost начнёт принимать соединения."""
    deadline = time.perf_counter() + max_wait
    while time.perf_counter() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except (socket.error, socket.gaierror, OSError):
            time.sleep(poll_interval)
    return False


def _check_hysteria_reachable(address: str, port: int, timeout: float) -> tuple[bool, float]:
    """
    Проверка доступности сервера Hysteria/Hysteria2 по TCP (порт открыт).
    Полная E2E-проверка через прокси требует отдельного клиента (Xray не поддерживает Hysteria).
    Возвращает (доступен, задержка_в_секундах).
    """
    try:
        start_time = time.perf_counter()
        with socket.create_connection((address, port), timeout=timeout):
            elapsed = time.perf_counter() - start_time
            return (True, elapsed)
    except (socket.error, socket.gaierror, OSError):
        return (False, timeout)  # При ошибке возвращаем таймаут как задержку
from .signals import register_process, unregister_process
from .utils import (
    check_geolocation_allowed,
    check_response_valid,
    get_geolocation,
    is_connection_error,
    make_request,
)
from .xray_manager import build_xray_config, kill_xray_process, run_xray

logger = logging.getLogger(__name__)


def check_key_e2e(vless_line: str, debug: bool = False, cache: Optional[dict] = None) -> tuple[str, bool, Optional[dict]]:
    """
    End-to-end проверка с расширенными возможностями.
    Возвращает (строка_ключа, доступен, метрики).
    Метрики содержат информацию о проверке (время ответа, геолокация и т.д.).
    """
    # debug параметр используется только для первого ключа и только если уровень логирования DEBUG
    should_debug_flag = should_debug_func(debug)
    
    # Проверка кэша
    if cache is not None and ENABLE_CACHE:
        key_hash = get_key_hash(vless_line)
        cached_result = check_cache(key_hash, cache)
        if cached_result is not None:
            if should_debug_flag:
                logger.debug(f"Результат из кэша для ключа: {key_hash[:8]}...")
            metrics = {
                "response_times": [],
                "geolocation": None,
                "successful_urls": 0,
                "failed_urls": 0,
                "total_requests": 0,
                "successful_requests": 0,
                "cached": True
            }
            return (vless_line, cached_result, metrics)
    
    metrics = {
        "response_times": [],
        "geolocation": None,
        "successful_urls": 0,
        "failed_urls": 0,
        "total_requests": 0,
        "successful_requests": 0,
        "cached": False
    }
    
    parsed = parse_proxy_url(vless_line)
    if not parsed:
        if should_debug_flag:
            logger.debug("Не удалось разобрать прокси-ссылку.")
        return (vless_line, False, metrics)

    # Hysteria/Hysteria2: Xray не поддерживает; проверяем только доступность хоста по TCP
    if parsed.get("protocol") in ("hysteria", "hysteria2"):
        timeout = CONNECT_TIMEOUT_SLOW if USE_ADAPTIVE_TIMEOUT else CONNECT_TIMEOUT
        ok, latency = _check_hysteria_reachable(parsed["address"], parsed["port"], float(timeout))
        # Сохраняем задержку в метрики для сортировки
        if ok:
            metrics["response_times"] = [latency]
        if cache is not None and ENABLE_CACHE:
            key_hash = get_key_hash(vless_line)
            cache[key_hash] = {"result": ok, "timestamp": time.time()}
        metrics["successful_urls"] = 1 if ok else 0
        metrics["failed_urls"] = 0 if ok else 1
        return (vless_line, ok, metrics)

    port = take_port()
    if port is None:
        if should_debug_flag:
            logger.debug("Нет свободного порта в пуле.")
        return (vless_line, False, metrics)
    
    # Добавляем процесс в список активных для обработки сигналов
    proc = None

    config = build_xray_config(parsed, port)
    fd, config_path = tempfile.mkstemp(suffix=".json", prefix="xray_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False)
    except Exception as e:
        try:
            os.close(fd)
        except OSError:
            pass
        return_port(port)
        if should_debug_flag:
            logger.debug(f"Ошибка записи конфига: {e}")
        return (vless_line, False, metrics)

    try:
        proc = run_xray(config_path, stderr_pipe=should_debug_flag)
        register_process(proc, port)
        waited = 0.0
        while waited < XRAY_STARTUP_WAIT:
            if proc.poll() is not None:
                break
            time.sleep(XRAY_STARTUP_POLL_INTERVAL)
            waited += XRAY_STARTUP_POLL_INTERVAL
        if proc.poll() is not None:
            if should_debug_flag and proc.stderr:
                err = proc.stderr.read().decode("utf-8", errors="replace")
                logger.debug(f"xray завершился сразу. stderr:\n{err}")
            unregister_process(proc, port)
            return (vless_line, False, metrics)

        if not _wait_for_port("127.0.0.1", port, XRAY_PORT_WAIT, XRAY_STARTUP_POLL_INTERVAL):
            if should_debug_flag:
                logger.debug("SOCKS-порт не открылся в течение XRAY_PORT_WAIT с")
            unregister_process(proc, port)
            return (vless_line, False, metrics)

        proxies = {
            "http": f"socks5h://127.0.0.1:{port}",
            "https": f"socks5h://127.0.0.1:{port}",
        }
        
        # Определяем таймаут
        timeout = CONNECT_TIMEOUT_SLOW if USE_ADAPTIVE_TIMEOUT else CONNECT_TIMEOUT
        
        # Строгий режим: N запросов к gstatic/generate_204 подряд, без повторов; таймаут как в мобильном клиенте
        if STRONG_STYLE_TEST:
            test_url = _CLIENT_TEST_HTTPS
            max_ok_time = STRONG_MAX_RESPONSE_TIME if STRONG_MAX_RESPONSE_TIME > 0 else MAX_RESPONSE_TIME
            # Таймаут одного запроса: STRONG_STYLE_TIMEOUT - общее время (connect + read), без завышения
            connect_t = max(3, min(10, int(STRONG_STYLE_TIMEOUT * 0.4)))
            read_t = max(5, STRONG_STYLE_TIMEOUT - connect_t)
            timeout_strong = (connect_t, read_t)
            attempts_needed = max(1, STRONG_ATTEMPTS)
            last_elapsed = 0.0
            for attempt in range(attempts_needed):
                if attempt > 0:
                    time.sleep(0.5)
                response, elapsed_time, error = make_request(test_url, proxies, timeout_strong)
                metrics["total_requests"] = metrics.get("total_requests", 0) + 1
                if response and not error and check_response_valid(response, 0, test_url):
                    if max_ok_time > 0 and elapsed_time > max_ok_time:
                        if should_debug_flag:
                            logger.debug(f"Строгий режим: превышено время ответа {elapsed_time:.2f}с > {max_ok_time}с")
                        unregister_process(proc, port)
                        return (vless_line, False, metrics)
                    last_elapsed = elapsed_time
                    if metrics.get("response_times") is None:
                        metrics["response_times"] = []
                    metrics["response_times"].append(elapsed_time)
                    continue
                if should_debug_flag:
                    logger.debug(f"Строгий режим: запрос не удался (попытка {attempt + 1}, error={error}, status={getattr(response, 'status_code', None)})")
                unregister_process(proc, port)
                return (vless_line, False, metrics)
            metrics["successful_requests"] = attempts_needed
            metrics["successful_urls"] = 1
            metrics["failed_urls"] = 0
            unregister_process(proc, port)
            return (vless_line, True, metrics)

        # Собираем все URL для проверки
        all_urls = []
        if TEST_URLS:
            all_urls.extend([(url, "http") for url in TEST_URLS])
        if TEST_URLS_HTTPS:
            all_urls.extend([(url, "https") for url in TEST_URLS_HTTPS])
        
        if not all_urls:
            if TEST_URL:
                all_urls = [(TEST_URL, "http")]
            else:
                if should_debug_flag:
                    logger.debug("Нет URL для проверки. Задайте TEST_URL или TEST_URLS.")
                unregister_process(proc, port)
                return (vless_line, False, metrics)
        
        # Проверка стабильности: несколько проходов
        stability_results = []
        all_url_results = {}  # Сохраняем результаты всех проверок стабильности
        for stability_check in range(STABILITY_CHECKS):
            if stability_check > 0:
                time.sleep(STABILITY_CHECK_DELAY)
            
            url_results = {}
            successful_urls_count = 0
            
            # Проверка каждого URL
            for url, url_type in all_urls:
                url_successful = False
                request_results = []
                
                # Множественные запросы к одному URL
                for request_num in range(REQUESTS_PER_URL):
                    if request_num > 0:
                        time.sleep(REQUEST_DELAY)
                    
                    # Повторные попытки с экспоненциальной задержкой
                    last_error = None
                    request_successful = False
                    
                    for retry_attempt in range(MAX_RETRIES + 1):
                        if retry_attempt > 0:
                            delay = RETRY_DELAY_BASE * (RETRY_DELAY_MULTIPLIER ** (retry_attempt - 1))
                            time.sleep(delay)
                        
                        response, elapsed_time, error = make_request(url, proxies, timeout)
                        metrics["total_requests"] += 1
                        
                        if response and not error:
                            if check_response_valid(response, MIN_RESPONSE_SIZE, url):
                                # Проверка времени ответа
                                if MAX_RESPONSE_TIME > 0 and elapsed_time > MAX_RESPONSE_TIME:
                                    if should_debug_flag:
                                        logger.debug(f"Превышено время ответа: {elapsed_time:.2f}с > {MAX_RESPONSE_TIME}с")
                                    continue
                                
                                metrics["response_times"].append(elapsed_time)
                                request_results.append(True)
                                metrics["successful_requests"] += 1
                                request_successful = True
                                break
                            else:
                                if should_debug_flag:
                                    logger.debug(f"Невалидный ответ: статус={response.status_code}, размер={len(response.content)}")
                        elif error:
                            last_error = error
                            if should_debug_flag and retry_attempt == MAX_RETRIES:
                                if is_connection_error(error):
                                    logger.debug(f"Ошибка соединения после {MAX_RETRIES + 1} попыток: {error}")
                                else:
                                    logger.debug(f"Ошибка запроса: {error}")
                        
                        # Если это connection error и есть еще попытки, продолжаем
                        if error and is_connection_error(error) and retry_attempt < MAX_RETRIES:
                            continue
                        elif error:
                            break
                    
                    request_results.append(request_successful)
                
                # Проверяем, достаточно ли успешных запросов к этому URL
                successful_requests = sum(request_results)
                if successful_requests >= MIN_SUCCESSFUL_REQUESTS:
                    url_successful = True
                    successful_urls_count += 1
                
                url_results[url] = url_successful
                
                # Короткое замыкание: если уже достаточно успешных URL - не проверяем остальные
                # (сохраняем качество: MIN_SUCCESSFUL_URLS по-прежнему требуется)
                # В строгом режиме проверяем все URL
                if not STRICT_MODE and successful_urls_count >= MIN_SUCCESSFUL_URLS:
                    if not REQUIRE_HTTPS:
                        break
                    # Если нужен HTTPS - выходим только когда есть хотя бы один успешный HTTPS
                    if any(url_results.get(u, False) for u, t in all_urls if t == "https"):
                        break
            
            # Проверка POST запросов (если включено)
            if TEST_POST_REQUESTS:
                post_url = all_urls[0][0] if all_urls else TEST_URL
                post_response, post_elapsed, post_error = make_request(
                    post_url, proxies, timeout, method="POST", post_data={"test": "data"}
                )
                metrics["total_requests"] += 1
                if post_response and not post_error and check_response_valid(post_response, MIN_RESPONSE_SIZE, post_url):
                    metrics["successful_requests"] += 1
                    metrics["response_times"].append(post_elapsed)
                elif should_debug_flag:
                    logger.debug(f"POST запрос не удался: {post_error}")
            
            # Проверка геолокации
            if CHECK_GEOLOCATION:
                geolocation = get_geolocation(proxies)
                if geolocation:
                    metrics["geolocation"] = geolocation
                    if not check_geolocation_allowed(geolocation, ALLOWED_COUNTRIES):
                        if should_debug_flag:
                            logger.debug(f"Геолокация не разрешена: {geolocation}")
                        unregister_process(proc, port)
                        return (vless_line, False, metrics)
            
            # Сохраняем результаты для этого прохода проверки стабильности
            for url, success in url_results.items():
                if url not in all_url_results:
                    all_url_results[url] = []
                all_url_results[url].append(success)
            
            # Проверка HTTPS для этой проверки стабильности
            https_check_passed = True
            if REQUIRE_HTTPS:
                https_urls = [url for url, url_type in all_urls if url_type == "https"]
                if https_urls:
                    https_successful = sum(1 for url in https_urls if url_results.get(url, False))
                    if https_successful == 0:
                        https_check_passed = False
                        if should_debug_flag:
                            logger.debug(f"Проверка стабильности {stability_check + 1}: нет успешных HTTPS URL")
            
            # Проверяем, достаточно ли успешных URL
            # В строгом режиме требуем успешного прохождения всех URL
            if STRICT_MODE and STRICT_MODE_REQUIRE_ALL:
                all_urls_passed = successful_urls_count == len(all_urls)
                stability_results.append(all_urls_passed and https_check_passed)
                if not all_urls_passed:
                    if should_debug_flag:
                        logger.debug(f"Строгий режим: не все URL успешны ({successful_urls_count}/{len(all_urls)})")
                    unregister_process(proc, port)
                    return (vless_line, False, metrics)
                if not https_check_passed:
                    if should_debug_flag:
                        logger.debug("Строгий режим: нет успешных HTTPS URL")
                    unregister_process(proc, port)
                    return (vless_line, False, metrics)
            else:
                stability_results.append(successful_urls_count >= MIN_SUCCESSFUL_URLS and https_check_passed)
        
        # Проверка стабильности: все проверки должны быть успешными
        if STABILITY_CHECKS > 1:
            all_stable = all(stability_results)
            if not all_stable:
                if should_debug_flag:
                    logger.debug(f"Нестабильное соединение: {sum(stability_results)}/{STABILITY_CHECKS} проверок успешно")
                unregister_process(proc, port)
                return (vless_line, False, metrics)
        
        # Проверка среднего времени ответа
        if metrics["response_times"]:
            avg_time = sum(metrics["response_times"]) / len(metrics["response_times"])
            metrics["avg_response_time"] = avg_time
            if MIN_AVG_RESPONSE_TIME > 0 and avg_time > MIN_AVG_RESPONSE_TIME:
                if should_debug_flag:
                    logger.debug(f"Среднее время ответа слишком велико: {avg_time:.2f}с > {MIN_AVG_RESPONSE_TIME}с")
                unregister_process(proc, port)
                return (vless_line, False, metrics)
        
        # Финальная проверка: достаточно ли успешных URL
        # Используем результаты последней проверки стабильности
        final_url_results = {}
        final_successful_count = 0
        if all_url_results:
            # Берем результаты последней проверки стабильности
            for url in all_urls:
                url_key = url[0]
                if url_key in all_url_results:
                    # URL считается успешным, если он успешен в последней проверке
                    final_url_results[url_key] = all_url_results[url_key][-1] if all_url_results[url_key] else False
                    if final_url_results[url_key]:
                        final_successful_count += 1
        else:
            # Fallback: если нет результатов проверки стабильности, используем пустые результаты
            final_url_results = {}
            final_successful_count = 0
        
        metrics["successful_urls"] = final_successful_count
        metrics["failed_urls"] = len(all_urls) - final_successful_count
        is_available = final_successful_count >= MIN_SUCCESSFUL_URLS
        
        # Проверка HTTPS, если требуется
        if REQUIRE_HTTPS:
            https_urls = [url for url, url_type in all_urls if url_type == "https"]
            if https_urls:
                https_successful = sum(1 for url in https_urls if final_url_results.get(url, False))
                if https_successful == 0:
                    if should_debug_flag:
                        checked = [u for u in https_urls if u in final_url_results]
                        not_checked = [u for u in https_urls if u not in final_url_results]
                        logger.debug(f"REQUIRE_HTTPS: нет успешных HTTPS URL (проверено: {len(checked)}, успешных: 0)")
                        if checked:
                            for u in checked:
                                logger.debug(f"  HTTPS {u} -> {final_url_results.get(u, False)}")
                        if not_checked:
                            logger.debug(f"  Не проверялись (короткое замыкание?): {not_checked}")
                        from config import VERIFY_HTTPS_SSL
                        if VERIFY_HTTPS_SSL:
                            logger.debug("  Совет: при ошибке SSL через прокси задайте VERIFY_HTTPS_SSL=false в .env")
                    is_available = False
            else:
                if should_debug_flag:
                    logger.debug("REQUIRE_HTTPS: нет HTTPS URL для проверки (TEST_URLS_HTTPS пуст?)")
                is_available = False
        
        # В строгом режиме требуем успешного прохождения всех URL
        if STRICT_MODE and STRICT_MODE_REQUIRE_ALL:
            is_available = final_successful_count == len(all_urls)
            if REQUIRE_HTTPS:
                https_urls = [url for url, url_type in all_urls if url_type == "https"]
                if https_urls:
                    https_successful = sum(1 for url in https_urls if final_url_results.get(url, False))
                    # В строгом режиме требуем успешного прохождения всех HTTPS URL
                    is_available = is_available and (https_successful == len(https_urls))
                else:
                    # Если REQUIRE_HTTPS=true, но нет HTTPS URL - это ошибка конфигурации
                    is_available = False
        
        # Сохранение в кэш
        if cache is not None and ENABLE_CACHE:
            key_hash = get_key_hash(vless_line)
            cache[key_hash] = {
                'result': is_available,
                'timestamp': time.time()
            }
        
        unregister_process(proc, port)
        return (vless_line, is_available, metrics)
        
    except FileNotFoundError:
        if should_debug_flag:
            import config
            logger.debug(f"Xray не найден (команда: {config.XRAY_CMD}). Установите Xray и добавьте в PATH или задайте XRAY_PATH.")
        if proc:
            unregister_process(proc, port)
        return (vless_line, False, metrics)
    except Exception as e:
        if should_debug_flag:
            logger.debug(f"Исключение: {e}")
            if proc and proc.stderr:
                try:
                    err = proc.stderr.read().decode("utf-8", errors="replace")
                    if err.strip():
                        logger.debug(f"stderr xray:\n{err}")
                except Exception:
                    pass
        if proc:
            unregister_process(proc, port)
        return (vless_line, False, metrics)
    finally:
        if proc is not None:
            unregister_process(proc, port)
            if should_debug_flag and proc.stderr is not None and proc.poll() is not None:
                try:
                    err = proc.stderr.read().decode("utf-8", errors="replace")
                    if err.strip():
                        logger.debug(f"stderr xray после завершения:\n{err}")
                except Exception:
                    pass
            kill_xray_process(proc, drain_stderr=True)
        try:
            os.unlink(config_path)
        except FileNotFoundError:
            pass
        return_port(port)
