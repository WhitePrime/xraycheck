#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Модуль парсинга прокси URL (VLESS, VMess, Trojan, Shadowsocks) и загрузки списков ключей.
"""

import base64
import json
import os
import requests
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote

from config import OUTPUT_ADD_DATE, OUTPUT_FILE
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
    """Имя файла результата: при OUTPUT_ADD_DATE=false — OUTPUT_FILE как есть; иначе база + (источник_ДДММГГГГ).txt."""
    if not OUTPUT_ADD_DATE:
        base, ext = os.path.splitext(OUTPUT_FILE)
        return f"{base or 'available'}{ext or '.txt'}"
    base, ext = os.path.splitext(OUTPUT_FILE)
    if not base:
        base = "available"
    if not ext:
        ext = ".txt"
    source = get_source_name(list_url)
    date = datetime.now().strftime("%d%m%Y")
    return f"{base} ({source}_{date}){ext}"


def fetch_list(url: str) -> str:
    """Загружает текст списка по URL."""
    r = requests.get(url, timeout=15)
    r.raise_for_status()
    return r.text


def load_urls_from_file(path: str) -> list[str]:
    """Читает файл с URL (по одному на строку), возвращает список непустых URL."""
    with open(path, encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip()]
    return urls


def parse_proxy_lines(text: str) -> list[tuple[str, str]]:
    """Возвращает список (прокси_ссылка, полная_строка) для строк с поддерживаемыми протоколами."""
    supported_protocols = ("vless://", "vmess://", "trojan://", "ss://")
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
    Поддерживает: VLESS, VMess, Trojan, Shadowsocks.
    Возвращает словарь для построения конфига xray или None при ошибке.
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
    
    console.print(f"[bold]Итого уникальных ключей:[/bold] {len(result)}\n")
    return ("merged", result)
