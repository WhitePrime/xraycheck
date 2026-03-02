#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Модуль парсинга прокси URL (VLESS, VMess, Trojan, Shadowsocks, Hysteria, Hysteria2) и загрузки списков ключей.
"""

import base64
import json
import os
import requests
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote

from .config import OUTPUT_ADD_DATE, OUTPUT_DIR, OUTPUT_FILE
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
)

console = Console()


def get_source_name(url_or_path: str) -> str:
    """Имя источника: последний сегмент URL path или basename файла без расширения."""
    if url_or_path.startswith("http://") or url_or_path.startswith("https://"):
        path = urlparse(url_or_path).path.rstrip("/")
        return path.split("/")[-1] if path else "list"
    return os.path.splitext(os.path.basename(url_or_path))[0] or "list"


def get_output_path(list_url: str) -> str:
    """Путь к файлу результата: OUTPUT_DIR/имя; при OUTPUT_ADD_DATE=false - OUTPUT_FILE как есть; иначе база + (источник_ДДММГГГГ).txt."""
    if not OUTPUT_ADD_DATE:
        base, ext = os.path.splitext(OUTPUT_FILE)
        name = f"{base or 'available'}{ext}"
    else:
        base, ext = os.path.splitext(OUTPUT_FILE)
        base = base or "available"
        ext = ext or ".txt"
        source = get_source_name(list_url)
        date = datetime.now().strftime("%d%m%Y")
        name = f"{base} ({source}_{date}){ext}"
    return os.path.join(OUTPUT_DIR, name) if OUTPUT_DIR else name


# Префиксы протоколов для проверки «уже раскодировано»
_SUBSCRIPTION_PROTOCOLS = ("vless://", "vmess://", "trojan://", "ss://", "hysteria://", "hysteria2://", "hy2://")


def normalize_proxy_link(link: str) -> str:
    """
    Возвращает ключ без фрагмента (всё после # - комментарий к ключу).
    Дедупликация notworkers и сравнение выполняются только по нормализованному ключу:
    два ключа считаются одним и тем же, если normalize_proxy_link(a) == normalize_proxy_link(b).
    """
    link = link.strip().split(maxsplit=1)[0].strip()
    if "#" in link:
        link = link.split("#", 1)[0].strip()
    return link


def load_notworkers(path: str) -> set[str]:
    """
    Читает файл с неактивными ключами (один ключ на строку).
    Возвращает множество нормализованных ссылок (без фрагмента #комментарий) для фильтрации и дедупликации.
    Пустые строки и строки-комментарии (# в начале) пропускаются. Если файла нет - пустое множество.
    Сравнение при фильтрации - по нормализованному ключу (полное совпадение ключа без комментария).
    """
    normalized_set, _ = load_notworkers_with_lines(path)
    return normalized_set


def load_notworkers_with_lines(path: str) -> tuple[set[str], dict[str, str]]:
    """
    Читает файл с неактивными ключами (один ключ на строку).
    Возвращает (множество нормализованных ссылок, отображение нормализованный_ключ -> полная_строка).
    Полная строка сохраняется как в файле (с комментарием после # и т.д.) для записи без обрезки.
    """
    result: set[str] = set()
    normalized_to_full: dict[str, str] = {}
    if not os.path.isfile(path):
        return result, normalized_to_full
    with open(path, encoding="utf-8") as f:
        for line in f:
            full_line = line.strip()
            if not full_line or full_line.startswith("#"):
                continue
            link = full_line.split(maxsplit=1)[0].strip()
            if link and any(link.startswith(p) for p in _SUBSCRIPTION_PROTOCOLS):
                norm = normalize_proxy_link(link)
                result.add(norm)
                normalized_to_full[norm] = full_line
    return result, normalized_to_full


def save_notworkers(path: str, normalized_to_full: dict[str, str]) -> None:
    """Записывает неактивные ключи в файл как есть (полная строка на каждую запись), отсортировано по нормализованному ключу для стабильного diff."""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for norm in sorted(normalized_to_full):
            full_line = normalized_to_full[norm]
            if full_line:
                f.write(full_line + "\n")


def load_keys_from_file(path: str) -> list[tuple[str, str]]:
    """
    Читает файл с прокси-ключами (один на строку). Возвращает список (ссылка, полная_строка).
    Пустые строки и строки, начинающиеся с #, пропускаются. Только строки с известным протоколом.
    """
    if not os.path.isfile(path):
        return []
    result: list[tuple[str, str]] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if any(line.startswith(p) for p in _SUBSCRIPTION_PROTOCOLS):
                link = line.split(maxsplit=1)[0].strip()
                if link:
                    result.append((link, line))
    return result


def _content_has_protocol_lines(text: str) -> bool:
    """Проверяет, есть ли в тексте строки, начинающиеся с известного протокола."""
    for line in text.splitlines():
        line = line.strip()
        if any(line.startswith(p) for p in _SUBSCRIPTION_PROTOCOLS):
            return True
    return False


def decode_subscription_content(text: str) -> str:
    """
    Декодирует контент подписки: если текст - base64 (типично для ссылок вроде nowmeow.pw/.../whitelist
    или gitverse.ru/.../whitelist.txt), возвращает раскодированный текст. Иначе возвращает исходный.
    """
    if not text or not text.strip():
        return text
    text = text.strip()
    # Уже есть ссылки с протоколами - не трогаем
    if _content_has_protocol_lines(text):
        return text
    # Убираем переносы строк внутри base64 (некоторые серверы отдают с переносами)
    raw = "".join(text.split())
    for encoding in (base64.standard_b64decode, base64.urlsafe_b64decode):
        try:
            padded = raw
            if len(padded) % 4:
                padded += "=" * (4 - len(padded) % 4)
            decoded = encoding(padded)
            if isinstance(decoded, bytes):
                decoded = decoded.decode("utf-8", errors="replace")
            decoded = decoded.strip()
            if decoded and _content_has_protocol_lines(decoded):
                return decoded
        except Exception:
            continue
    return text


def fetch_list(url: str) -> str:
    """Загружает текст списка по URL. Поддерживает ответ в base64 (формат подписок)."""
    # Валидация URL перед использованием
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Некорректный URL: {url}")
        # Проверка на управляющие символы
        if any(ord(c) < 32 and c not in '\t\n\r' for c in url):
            raise ValueError(f"URL содержит управляющие символы: {url}")
    except Exception as e:
        raise ValueError(f"Ошибка валидации URL: {e}")
    
    r = requests.get(url, timeout=15)
    r.raise_for_status()
    return decode_subscription_content(r.text)


def load_urls_from_file(path: str) -> list[str]:
    """Читает файл с URL (по одному на строку), возвращает список непустых URL.
    Обрабатывает случаи, когда в строке несколько URL, разделенных пробелами."""
    urls = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Разбиваем строку по пробелам и берем только валидные URL
            parts = line.split()
            for part in parts:
                part = part.strip()
                # Проверяем, что это похоже на URL
                if part.startswith(("http://", "https://")):
                    urls.append(part)
    return urls


def parse_proxy_lines(text: str) -> list[tuple[str, str]]:
    """Возвращает список (прокси_ссылка, полная_строка) для строк с поддерживаемыми протоколами."""
    supported_protocols = ("vless://", "vmess://", "trojan://", "ss://", "hysteria://", "hysteria2://", "hy2://")
    result = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # Проверяем, начинается ли строка с одного из поддерживаемых протоколов
        for protocol in supported_protocols:
            if line.startswith(protocol):
                link = line.split(maxsplit=1)[0].strip()
                if link:
                    result.append((link, line))
                break
    return result


# Обратная совместимость
def parse_vless_lines(text: str) -> list[tuple[str, str]]:
    """Устаревшая функция, используйте parse_proxy_lines. Оставлена для совместимости."""
    return parse_proxy_lines(text)


def parse_vless_url(vless_url: str) -> dict | None:
    """
    Парсит vless://uuid@host:port?query#fragment.
    Возвращает словарь для построения конфига xray или None при ошибке.
    """
    try:
        parsed = urlparse(vless_url)
        if parsed.scheme != "vless" or not parsed.netloc:
            return None
        netloc = parsed.netloc
        if "@" not in netloc:
            return None
        userinfo, host_port = netloc.rsplit("@", 1)
        uuid = userinfo
        if ":" in host_port:
            host, _, port_str = host_port.rpartition(":")
            port = int(port_str)
        else:
            host, port = host_port, 443
        if not host or not uuid:
            return None

        query = parse_qs(parsed.query or "", keep_blank_values=True)

        def get(name: str, default: str = "") -> str:
            a = query.get(name, [default])
            return (a[0] or default).strip()

        network = get("type", "tcp").lower()
        security = get("security", "reality").lower()
        flow = get("flow", "")
        fp = get("fp", "chrome")
        pbk = get("pbk", "")
        sid = get("sid", "")
        sni = get("sni", "")
        mode = get("mode", "")  # для xhttp: mode=auto

        return {
            "protocol": "vless",
            "uuid": uuid,
            "address": host,
            "port": port,
            "network": network,
            "security": security,
            "flow": flow,
            "fingerprint": fp,
            "publicKey": pbk,
            "shortId": sid,
            "serverName": sni,
            "mode": mode,
        }
    except Exception:
        return None


def parse_vmess_url(vmess_url: str) -> dict | None:
    """
    Парсит vmess://base64(json) или vmess://userInfo@host:port?params.
    Возвращает словарь для построения конфига xray или None при ошибке.
    """
    try:
        parsed = urlparse(vmess_url)
        if parsed.scheme != "vmess" or not parsed.netloc:
            return None
        
        # Попытка 1: base64-encoded JSON формат (vmess://base64)
        if "@" not in parsed.netloc:
            try:
                # Убираем схему и декодируем base64
                base64_part = vmess_url.replace("vmess://", "").split("#")[0]
                # Добавляем padding если нужно
                padding = 4 - len(base64_part) % 4
                if padding != 4:
                    base64_part += "=" * padding
                decoded = base64.urlsafe_b64decode(base64_part).decode("utf-8")
                vmess_json = json.loads(decoded)
                
                # Извлекаем данные из JSON
                address = vmess_json.get("add", "")
                port = int(vmess_json.get("port", 443))
                user_id = vmess_json.get("id", "")
                alter_id = int(vmess_json.get("aid", 0))
                security = vmess_json.get("scy", "auto").lower()
                network = vmess_json.get("net", "tcp").lower()
                tls = vmess_json.get("tls", "").lower()
                sni = vmess_json.get("sni", "")
                
                # Параметры для разных типов сетей
                ws_path = vmess_json.get("path", "")
                ws_host = vmess_json.get("host", "")
                grpc_service_name = vmess_json.get("ps", "")
                
                return {
                    "protocol": "vmess",
                    "address": address,
                    "port": port,
                    "id": user_id,
                    "alterId": alter_id,
                    "security": security,
                    "network": network,
                    "tls": tls,
                    "serverName": sni,
                    "wsPath": ws_path,
                    "wsHost": ws_host,
                    "grpcServiceName": grpc_service_name,
                }
            except Exception:
                pass
        
        # Попытка 2: URL формат (vmess://userInfo@host:port?params)
        netloc = parsed.netloc
        if "@" in netloc:
            userinfo, host_port = netloc.rsplit("@", 1)
            if ":" in host_port:
                host, _, port_str = host_port.rpartition(":")
                port = int(port_str)
            else:
                host, port = host_port, 443
            
            query = parse_qs(parsed.query or "", keep_blank_values=True)
            def get(name: str, default: str = "") -> str:
                a = query.get(name, [default])
                return (a[0] or default).strip()
            
            # Декодируем userinfo (может быть base64)
            try:
                userinfo_decoded = base64.urlsafe_b64decode(userinfo + "==").decode("utf-8")
                if ":" in userinfo_decoded:
                    user_id, alter_id_str = userinfo_decoded.split(":", 1)
                    alter_id = int(alter_id_str) if alter_id_str.isdigit() else 0
                else:
                    user_id = userinfo_decoded
                    alter_id = 0
            except Exception:
                user_id = userinfo
                alter_id = 0
            
            network = get("network", "tcp").lower()
            tls = get("tls", "").lower()
            sni = get("sni", "")
            ws_path = get("wsPath", "")
            ws_host = get("wsHost", "")
            
            return {
                "protocol": "vmess",
                "address": host,
                "port": port,
                "id": user_id,
                "alterId": alter_id,
                "security": "auto",
                "network": network,
                "tls": tls,
                "serverName": sni,
                "wsPath": ws_path,
                "wsHost": ws_host,
            }
        
        return None
    except Exception:
        return None


def parse_trojan_url(trojan_url: str) -> dict | None:
    """
    Парсит trojan://password@host:port?params#tag.
    Возвращает словарь для построения конфига xray или None при ошибке.
    """
    try:
        parsed = urlparse(trojan_url)
        if parsed.scheme != "trojan" or not parsed.netloc:
            return None
        
        netloc = parsed.netloc
        if "@" not in netloc:
            return None
        
        password, host_port = netloc.rsplit("@", 1)
        password = unquote(password)
        
        if ":" in host_port:
            host, _, port_str = host_port.rpartition(":")
            port = int(port_str)
        else:
            host, port = host_port, 443
        
        if not host or not password:
            return None
        
        query = parse_qs(parsed.query or "", keep_blank_values=True)
        def get(name: str, default: str = "") -> str:
            a = query.get(name, [default])
            return (a[0] or default).strip()
        
        network = get("type", "tcp").lower()
        sni = get("sni", "")
        ws_path = get("wsPath", "")
        ws_host = get("host", "")
        grpc_service_name = get("serviceName", "")
        
        return {
            "protocol": "trojan",
            "address": host,
            "port": port,
            "password": password,
            "network": network,
            "serverName": sni,
            "wsPath": ws_path,
            "wsHost": ws_host,
            "grpcServiceName": grpc_service_name,
        }
    except Exception:
        return None


def parse_hysteria_url(hysteria_url: str) -> dict | None:
    """
    Парсит hysteria://host:port?protocol=udp&auth=...&peer=... (Hysteria v1, Shadowrocket-стиль).
    Возвращает словарь с полями для идентификации и проверки; Xray не поддерживает Hysteria.
    """
    try:
        parsed = urlparse(hysteria_url)
        if parsed.scheme != "hysteria" or not parsed.netloc:
            return None
        host_port = parsed.netloc
        if ":" in host_port:
            host, _, port_str = host_port.rpartition(":")
            port = int(port_str)
        else:
            host, port = host_port, 443
        if not host:
            return None
        query = parse_qs(parsed.query or "", keep_blank_values=True)
        def get(name: str, default: str = "") -> str:
            a = query.get(name, [default])
            return (a[0] or default).strip()
        return {
            "protocol": "hysteria",
            "address": host,
            "port": port,
            "auth": get("auth", ""),
            "peer": get("peer", ""),
            "insecure": get("insecure", ""),
            "obfs": get("obfs", ""),
            "obfsParam": get("obfsParam", ""),
            "alpn": get("alpn", "hysteria"),
        }
    except Exception:
        return None


def parse_hysteria2_url(hysteria2_url: str) -> dict | None:
    """
    Парсит hysteria2://[auth@]hostname[:port]/?params или hy2:// (Hysteria 2).
    Возвращает словарь с полями для идентификации; Xray не поддерживает Hysteria2.
    """
    try:
        # Нормализуем схему: hy2 -> hysteria2
        url = hysteria2_url.strip()
        if url.startswith("hy2://"):
            url = "hysteria2://" + url[6:]
        parsed = urlparse(url)
        if parsed.scheme != "hysteria2" or not parsed.hostname:
            return None
        host = parsed.hostname or ""
        port = parsed.port if parsed.port is not None else 443
        auth = (parsed.username or "")
        if parsed.password:
            auth = f"{parsed.username or ''}:{parsed.password}"
        query = parse_qs(parsed.query or "", keep_blank_values=True)
        def get(name: str, default: str = "") -> str:
            a = query.get(name, [default])
            return (a[0] or default).strip()
        return {
            "protocol": "hysteria2",
            "address": host,
            "port": port,
            "auth": auth,
            "sni": get("sni", ""),
            "insecure": get("insecure", ""),
            "obfs": get("obfs", ""),
            "obfsPassword": get("obfs-password", ""),
            "pinSHA256": get("pinSHA256", ""),
        }
    except Exception:
        return None


def parse_shadowsocks_url(ss_url: str) -> dict | None:
    """
    Парсит ss://base64(method:password)@host:port или ss://method:password@host:port.
    Возвращает словарь для построения конфига xray или None при ошибке.
    """
    try:
        parsed = urlparse(ss_url)
        if parsed.scheme != "ss" or not parsed.netloc:
            return None
        
        netloc = parsed.netloc
        method = ""
        password = ""
        
        if "@" in netloc:
            userinfo, host_port = netloc.rsplit("@", 1)
            
            # Попытка декодировать base64
            try:
                padding = 4 - len(userinfo) % 4
                if padding != 4:
                    userinfo += "=" * padding
                decoded = base64.urlsafe_b64decode(userinfo).decode("utf-8")
                if ":" in decoded:
                    method, password = decoded.split(":", 1)
                else:
                    method = decoded
            except Exception:
                # Если не base64, пробуем как plain text
                if ":" in userinfo:
                    method, password = userinfo.split(":", 1)
                else:
                    method = userinfo
            
            if ":" in host_port:
                host, _, port_str = host_port.rpartition(":")
                port = int(port_str)
            else:
                host, port = host_port, 8388
        else:
            # Старый формат: ss://base64(method:password@host:port)
            try:
                base64_part = ss_url.replace("ss://", "").split("#")[0]
                padding = 4 - len(base64_part) % 4
                if padding != 4:
                    base64_part += "=" * padding
                decoded = base64.urlsafe_b64decode(base64_part).decode("utf-8")
                if "@" in decoded:
                    userinfo, host_port = decoded.rsplit("@", 1)
                    if ":" in userinfo:
                        method, password = userinfo.split(":", 1)
                    else:
                        method = userinfo
                    if ":" in host_port:
                        host, _, port_str = host_port.rpartition(":")
                        port = int(port_str)
                    else:
                        host, port = host_port, 8388
                else:
                    return None
            except Exception:
                return None
        
        if not host or not method or not password:
            return None
        
        return {
            "protocol": "shadowsocks",
            "address": host,
            "port": port,
            "method": method,
            "password": password,
        }
    except Exception:
        return None


def parse_proxy_url(proxy_url: str) -> dict | None:
    """
    Универсальный парсер прокси URL. Определяет протокол и вызывает соответствующий парсер.
    Поддерживает: VLESS, VMess, Trojan, Shadowsocks, Hysteria, Hysteria2.
    Возвращает словарь для построения конфига xray (или для проверки) или None при ошибке.
    """
    if not proxy_url:
        return None
    
    proxy_url = proxy_url.strip()
    
    if proxy_url.startswith("vless://"):
        return parse_vless_url(proxy_url)
    elif proxy_url.startswith("vmess://"):
        return parse_vmess_url(proxy_url)
    elif proxy_url.startswith("trojan://"):
        return parse_trojan_url(proxy_url)
    elif proxy_url.startswith("ss://"):
        return parse_shadowsocks_url(proxy_url)
    elif proxy_url.startswith("hysteria://"):
        return parse_hysteria_url(proxy_url)
    elif proxy_url.startswith("hysteria2://") or proxy_url.startswith("hy2://"):
        return parse_hysteria2_url(proxy_url)
    
    return None


def load_merged_keys(links_file: str) -> tuple[str, list[tuple[str, str]]]:
    """
    Режим merge: читает ссылки из links_file, загружает списки по каждой,
    объединяет ключи (дедупликация по ссылке, первое вхождение). Возвращает
    (имя_источника_для_вывода, список (vless_ссылка, полная_строка)).
    """
    urls = load_urls_from_file(links_file)
    if not urls:
        raise ValueError(f"В файле {links_file} нет ссылок")
    seen_links: set[str] = set()
    result: list[tuple[str, str]] = []
    total_urls = len(urls)
    
    # Используем прогресс-бар для динамического обновления
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("({task.completed}/{task.total})"),
        console=console
    ) as progress:
        task = progress.add_task(
            f"[cyan]Парсинг и объединение ключей из {total_urls} ссылок ({links_file})...[/cyan]",
            total=total_urls
        )
        
        for idx, url in enumerate(urls, 1):
            try:
                text = fetch_list(url)
                parsed = parse_proxy_lines(text)
                new_count = 0
                for link, full in parsed:
                    if link not in seen_links:
                        seen_links.add(link)
                        result.append((link, full))
                        new_count += 1
                
                # Обновляем прогресс-бар с информацией
                progress.update(
                    task,
                    advance=1,
                    description=f"[cyan]Парсинг ссылок...[/cyan] [{idx}/{total_urls}] получено {len(parsed)} ключей, новых {new_count}, всего: {len(result)}"
                )
            except (requests.RequestException, requests.exceptions.InvalidURL, OSError, ValueError) as e:
                # При ошибке загрузки или валидации URL помечаем URL и продолжаем
                error_msg = str(e)
                # Обрезаем длинные сообщения об ошибках
                if len(error_msg) > 100:
                    error_msg = error_msg[:97] + "..."
                console.print(f"[yellow][{idx}/{total_urls}][/yellow] [red]Ошибка загрузки:[/red] {error_msg}")
                progress.update(
                    task,
                    advance=1,
                    description=f"[cyan]Парсинг ссылок...[/cyan] [{idx}/{total_urls}] [red]Ошибка:[/red] (пропущено)"
                )
                continue
    
    console.print(f"[bold]Итого из {links_file}:[/bold] {len(result)} записей (уникальных по ссылке)")
    console.print("")
    return ("merged", result)
