#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Модуль парсинга VLESS URL и загрузки списков ключей.
"""

import os
import requests
from datetime import datetime
from urllib.parse import urlparse, parse_qs

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


def parse_vless_lines(text: str) -> list[tuple[str, str]]:
    """Возвращает список (vless_ссылка, полная_строка) для каждой строки с vless://."""
    result = []
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("vless://"):
            continue
        link = line.split(maxsplit=1)[0].strip()
        if link:
            result.append((link, line))
    return result


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
            parsed = parse_vless_lines(text)
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
