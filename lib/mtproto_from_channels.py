#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Сбор MTProto-прокси из публичных Telegram-каналов (через веб-интерфейс t.me).

Источник каналов:
  - переменная окружения TG_CHANNEL (строка с каналами построчно),
    пример значения:
        t.me/mtpro_xyz
        https://t.me/s/another_channel
        mtpro_other

Ограничение по времени:
  - флаг --hours (по умолчанию 24) - сколько последних часов смотреть в ленте
    каждого канала. Фильтрация делается по timestamp'ам в HTML (атрибут
    <time datetime="...">) на странице t.me/s/<channel>.

Выход:
  - файл с уникальными прокси в формате, совместимом с mtproto_checker.py
    (по умолчанию configs/mtproto_channels).
"""

from __future__ import annotations

import argparse
import datetime as dt
import html as _html
import os
import re
import sys
from typing import Iterable, List, Tuple
from urllib.parse import parse_qs, urlencode, urlparse

import requests
from bs4 import BeautifulSoup  # type: ignore

try:
    # Запуск как `python -m lib.mtproto_from_channels` (рекомендуемый режим)
    from .mtproto_checker import _load_raw_lines_from_text, _parse_mtproto
except ImportError:  # fallback для запуска как скрипта `python lib/mtproto_from_channels.py`
    from mtproto_checker import _load_raw_lines_from_text, _parse_mtproto

_PROXY_URL_RE = re.compile(
    r"(?:tg://proxy\?[^\"<>\s]+|https?://t\.me/proxy\?[^\"<>\s]+)",
    flags=re.IGNORECASE,
)


def _env_str(name: str, default: str = "") -> str:
    v = os.environ.get(name, "")
    return v if v is not None else default


def _normalize_channel_slug(raw: str) -> str | None:
    """
    Приводит строку из TG_CHANNEL к слагу канала (без префикса t.me/, @ и т.п.).
    """
    s = (raw or "").strip()
    if not s:
        return None
    # Частый формат без схемы: t.me/slug или t.me/s/slug
    if s.startswith(("t.me/", "telegram.me/")):
        s = "https://" + s
    # URL вида https://t.me/slug или https://t.me/s/slug
    if s.startswith("http://") or s.startswith("https://"):
        p = urlparse(s)
        path = p.path.lstrip("/")
        if not path:
            return None
        parts = path.split("/")
        # t.me/s/slug -> slug, t.me/slug -> slug
        if parts[0] == "s" and len(parts) >= 2:
            return parts[1]
        return parts[0]
    # Форматы @slug или просто slug
    if s.startswith("@"):
        s = s[1:]
    s = s.strip("/")
    return s or None


def _iter_channels_from_env(env_key: str = "TG_CHANNEL") -> Iterable[str]:
    value = _env_str(env_key, "")
    for line in value.splitlines():
        slug = _normalize_channel_slug(line)
        if slug:
            yield slug


def _fetch_channel_page(slug: str) -> str | None:
    """
    Получает HTML публичного канала через веб-интерфейс t.me/s/<slug>.
    """
    url = f"https://t.me/s/{slug}"
    try:
        r = requests.get(
            url,
            timeout=20,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; XRayCheck MTProto scraper)"
            },
        )
        if r.status_code != 200:
            print(f"[warn] {slug}: HTTP {r.status_code} для {url}", file=sys.stderr)
            return None
        return r.text
    except requests.RequestException as e:
        print(f"[warn] {slug}: ошибка запроса {e}", file=sys.stderr)
        return None


def _fetch_channel_page_before(slug: str, before_msg_id: int | None) -> str | None:
    """
    Получает HTML публичного канала через веб-интерфейс t.me/s/<slug>
    с пагинацией по параметру ?before=<message_id>.
    """
    base = f"https://t.me/s/{slug}"
    url = base if before_msg_id is None else f"{base}?{urlencode({'before': before_msg_id})}"
    try:
        r = requests.get(
            url,
            timeout=20,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; XRayCheck MTProto scraper)"
            },
        )
        if r.status_code != 200:
            print(f"[warn] {slug}: HTTP {r.status_code} для {url}", file=sys.stderr)
            return None
        return r.text
    except requests.RequestException as e:
        print(f"[warn] {slug}: ошибка запроса {e}", file=sys.stderr)
        return None


def _extract_messages_with_time(
    html: str,
) -> List[Tuple[dt.datetime, str]]:
    """
    Вытаскивает пары (datetime, text) для сообщений с HTML-страницы t.me/s.
    """
    soup = BeautifulSoup(html, "html.parser")
    result: List[Tuple[dt.datetime, str]] = []

    # Telegram периодически меняет обёртки. Поддерживаем оба варианта:
    # - div.tgme_widget_message_wrap
    # - div.tgme_widget_message
    nodes = soup.select("div.tgme_widget_message_wrap") or soup.select(
        "div.tgme_widget_message"
    )

    for msg in nodes:
        # Достаём текст, но основной поиск ссылок сделаем по HTML сообщения (href/текст).
        text_block = msg.select_one("div.tgme_widget_message_text") or msg.select_one(
            "div.tgme_widget_message_text.js-message_text"
        )
        text = text_block.get_text("\n", strip=True) if text_block else ""
        # Обычно time лежит внутри a.tgme_widget_message_date > time
        time_tag = msg.select_one("a.tgme_widget_message_date time") or msg.select_one("time")
        if not time_tag:
            continue
        dt_str = time_tag.get("datetime")
        if not dt_str:
            continue
        try:
            # Пример: 2026-03-16T20:30:45+00:00
            ts = dt.datetime.fromisoformat(dt_str)
        except ValueError:
            continue
        # Нормализуем к UTC, если без таймзоны - считаем UTC
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=dt.timezone.utc)
        else:
            ts = ts.astimezone(dt.timezone.utc)
        # Храним HTML блока сообщения, чтобы точно извлечь ссылки с query-параметрами.
        result.append((ts, str(msg) + ("\n" + text if text else "")))
    return result


def _collect_proxies_from_text_block(text_or_html: str) -> List[str]:
    """
    Ищет подстроки вида tg://proxy? и t.me/proxy? в тексте сообщения.
    Возвращает список «сырых» строк-кандидатов (потом нормализуются).
    """
    # Ищем URL в HTML (href) и в тексте (если URL выведен как текст).
    found = _PROXY_URL_RE.findall(text_or_html or "")
    # В href обычно встречается &amp; - раскодируем HTML-сущности.
    out: List[str] = []
    for s in found:
        if not s:
            continue
        u = _html.unescape(s).strip()
        if u:
            out.append(u)
    return out


def _extract_min_msg_id(html: str, slug: str) -> int | None:
    """
    Находит минимальный message_id на странице (для перехода на более старые сообщения через ?before=).
    Telegram кладёт идентификатор в атрибут data-post="slug/12345".
    """
    soup = BeautifulSoup(html, "html.parser")
    ids: list[int] = []
    for node in soup.select("[data-post]"):
        v = node.get("data-post") or ""
        if not v:
            continue
        # ожидаем "slug/12345"
        if "/" not in v:
            continue
        ch, mid = v.split("/", 1)
        if ch != slug:
            continue
        try:
            ids.append(int(mid))
        except ValueError:
            continue
    return min(ids) if ids else None


def _key_from_proxy_url(url: str) -> tuple[str, int, str] | None:
    """
    Возвращает ключ для дедупликации MTProto-прокси: (server, port, secret_or_empty).
    Поддерживает:
      - tg://proxy?server=...&port=...&secret=...
      - https://t.me/proxy?server=...&port=...&secret=... (secret может отсутствовать)
    """
    s = (url or "").strip()
    if not s:
        return None
    try:
        p = urlparse(s)
    except Exception:
        return None
    if p.scheme not in ("tg", "http", "https"):
        return None
    # tg://proxy?...
    if p.scheme == "tg" and p.netloc != "proxy":
        return None
    # https://t.me/proxy?...
    if p.scheme in ("http", "https"):
        if (p.netloc or "").lower() not in ("t.me", "telegram.me"):
            return None
        if (p.path or "").rstrip("/") != "/proxy":
            return None
    qs = parse_qs(p.query or "")
    server = (qs.get("server", [None])[0] or "").strip()
    port_s = (qs.get("port", [None])[0] or "").strip()
    if not server or not port_s:
        return None
    try:
        port = int(port_s)
    except ValueError:
        return None
    secret = (qs.get("secret", [""])[0] or "").strip()
    return (server, port, secret)


def collect_mtproto_from_channels(
    channels: Iterable[str],
    hours: int,
    *,
    allow_incomplete: bool,
) -> List[str]:
    """
    Возвращает список нормализованных MTProto-прокси, найденных
    на страницах t.me/s/<channel> за последние N часов.
    """
    now = dt.datetime.now(dt.timezone.utc)
    delta = dt.timedelta(hours=max(1, hours))
    # Собираем кандидаты отдельно по каждому источнику (каналу),
    # чтобы можно было вывести статистику "№ источника -> сколько прокси".
    raw_by_channel: list[tuple[str, List[str]]] = []

    for slug in channels:
        channel_raw: List[str] = []
        before: int | None = None
        seen_befores: set[int] = set()

        while True:
            html = _fetch_channel_page_before(slug, before)
            if not html:
                break

            messages = _extract_messages_with_time(html)
            if not messages:
                break

            # Собираем кандидаты только из сообщений в окне
            page_oldest_ts: dt.datetime | None = None
            any_in_window = False
            for ts, text in messages:
                page_oldest_ts = ts if page_oldest_ts is None else min(page_oldest_ts, ts)
                if now - ts > delta:
                    continue
                any_in_window = True
                channel_raw.extend(_collect_proxies_from_text_block(text))

            # Если на странице уже нет сообщений в окне и она старше окна - можно останавливаться.
            if page_oldest_ts is not None and now - page_oldest_ts > delta and not any_in_window:
                break

            # Переходим на следующую страницу назад по before=<min_id_on_page>
            min_id = _extract_min_msg_id(html, slug)
            if min_id is None:
                break
            if min_id in seen_befores:
                break
            seen_befores.add(min_id)
            before = min_id

        raw_by_channel.append((slug, channel_raw))

    # Нормализуем и дедуплицируем внутри каждого канала, чтобы статистика была честной.
    per_channel_normalized: list[tuple[str, List[str]]] = []
    for slug, raw_lines in raw_by_channel:
        if not raw_lines:
            per_channel_normalized.append((slug, []))
            continue
        normalized_input = "\n".join(raw_lines)
        lines = _load_raw_lines_from_text(normalized_input)
        seen_keys_local: set[tuple[str, int, str]] = set()
        out_local: List[str] = []
        for line in lines:
            key = _key_from_proxy_url(line)
            if key is not None:
                if key in seen_keys_local:
                    continue
                seen_keys_local.add(key)
                out_local.append(line)
                continue
            parsed = _parse_mtproto(line, strict=True, allow_incomplete=allow_incomplete)
            if not parsed:
                continue
            _, _, _normalized, key2 = parsed
            if key2 in seen_keys_local:
                continue
            seen_keys_local.add(key2)
            out_local.append(line)
        per_channel_normalized.append((slug, out_local))

    # Печатаем статистику в stdout (удобно смотреть в логах GitHub Actions).
    print("Статистика по источникам (TG channels):")
    print("| № | Прокси |")
    print("|---:|---:|")
    for idx, (_slug, items) in enumerate(per_channel_normalized, start=1):
        print(f"| {idx} | {len(items)} |")
    print("")

    # Собираем общий список кандидатов (после per-channel нормализации),
    # дальше делаем глобальную дедупликацию по ключу как и раньше.
    all_lines: List[str] = []
    for _, items in per_channel_normalized:
        all_lines.extend(items)

    if not all_lines:
        return []

    # ВАЖНО: сохраняем в исходном формате (как просили), но дедуплицируем по ключу.
    # При отсутствии secret (часто для t.me/proxy) ключ будет (server,port,"").
    seen_keys: set[tuple[str, int, str]] = set()
    out: List[str] = []
    for line in all_lines:
        # 1) Сначала пробуем извлечь ключ из URL напрямую (быстрее и надёжно для t.me/proxy).
        key = _key_from_proxy_url(line)
        if key is not None:
            if key in seen_keys:
                continue
            seen_keys.add(key)
            out.append(line)
            continue

        # 2) Фолбэк: используем существующий парсер mtproto_checker.py
        parsed = _parse_mtproto(line, strict=True, allow_incomplete=allow_incomplete)
        if not parsed:
            continue
        _, _, _normalized, key2 = parsed
        if key2 in seen_keys:
            continue
        seen_keys.add(key2)
        # line уже содержит оригинальный tg://proxy? или https://t.me/proxy? (после unescape)
        out.append(line)
    return out


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="mtproto_from_channels.py",
        description=(
            "Сбор MTProto-прокси из публичных Telegram-каналов (t.me/s/<channel>) "
            "за последние N часов."
        ),
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=24,
        help="Период в часах для отбора сообщений (default: 24)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=os.path.join("configs", "mtproto_channels"),
        help="Файл для вывода прокси (default: configs/mtproto_channels)",
    )
    parser.add_argument(
        "--allow-incomplete",
        action="store_true",
        default=True,
        help=(
            "Сохранять ссылки без secret как HOST:PORT (полезно для каналов, "
            "которые публикуют t.me/proxy без secret). По умолчанию включено."
        ),
    )
    args = parser.parse_args()

    channels = list(_iter_channels_from_env())
    if not channels:
        print(
            "TG_CHANNEL не задан или пуст. "
            "Укажите список каналов в переменной окружения TG_CHANNEL (по одному на строку).",
            file=sys.stderr,
        )
        sys.exit(1)

    proxies = collect_mtproto_from_channels(
        channels, args.hours, allow_incomplete=bool(args.allow_incomplete)
    )
    if not proxies:
        print("Не найдено ни одного MTProto-прокси в указанных каналах за заданный период.")
        # Создаём пустой файл, чтобы downstream-скрипты могли это учитывать.
        out_dir = os.path.dirname(args.output)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            pass
        sys.exit(0)

    out_dir = os.path.dirname(args.output)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    text = "\n".join(proxies) + "\n"
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(text)

    print(
        f"Собрано MTProto-прокси: {len(proxies)} из {len(channels)} каналов. "
        f"Результат записан в {args.output}"
    )


if __name__ == "__main__":
    main()

