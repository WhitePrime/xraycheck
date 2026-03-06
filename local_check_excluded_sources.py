#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Запуск (из корня репозитория):
  python local_check_excluded_sources.py
  python local_check_excluded_sources.py links_alt.txt

Переменные окружения:
  - EXCLUDE_ENDPOINTS          - построчно host:port или host
  - EXCLUDE_ENDPOINTS_FILE     - путь к файлу с исключениями (по умолчанию configs/exclude_endpoints)
  - EXCLUDE_ENDPOINTS_LOG_DETAILS=true/false - печатать ли подробные совпадения по строкам списка.
"""

import os
import sys
from typing import Optional


def _bool_env(name: str, default: bool = False) -> bool:
    v = (os.environ.get(name) or "").strip().lower()
    if not v:
        return default
    return v in ("1", "true", "yes", "on")


def main(argv: Optional[list[str]] = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Путь к links.txt можно переопределить аргументом
    links_path = argv[0] if argv else "links.txt"

    # Готовим импорт модулей проекта
    root_dir = os.path.dirname(os.path.abspath(__file__))
    if root_dir not in sys.path:
        sys.path.insert(0, root_dir)

    from filter_excluded_endpoints import (  # type: ignore
        _parse_exclude_lines,
        load_exclude_set_from_file,
        is_excluded,
    )
    from lib.parsing import load_urls_from_file, fetch_list, parse_proxy_url  # type: ignore

    # Загружаем правила исключения (тот же приоритет, что в filter_excluded_endpoints)
    var_content = (os.environ.get("EXCLUDE_ENDPOINTS") or "").strip()
    if var_content:
        exact_endpoints, hosts_only = _parse_exclude_lines(var_content.splitlines())
        filter_source = "EXCLUDE_ENDPOINTS"
    else:
        filepath = os.environ.get("EXCLUDE_ENDPOINTS_FILE", "configs/exclude_endpoints").strip()
        exact_endpoints, hosts_only = load_exclude_set_from_file(filepath)
        filter_source = filepath or "<not set>"

    if not exact_endpoints and not hosts_only:
        print("Нет правил исключения: EXCLUDE_ENDPOINTS пуст и файл EXCLUDE_ENDPOINTS_FILE не содержит записей.")
        return

    if not os.path.isfile(links_path):
        print(f"Файл links не найден: {links_path}")
        return

    urls = load_urls_from_file(links_path)
    if not urls:
        print(f"В {links_path} нет URL для обработки.")
        return

    detailed = _bool_env("EXCLUDE_ENDPOINTS_LOG_DETAILS", False)

    print(f"Источник правил: {filter_source}")
    print(f"Точных endpoint'ов: {len(exact_endpoints)}, по host: {len(hosts_only)}")
    print(f"Файл ссылок: {links_path}, всего URL: {len(urls)}")
    print()

    def extract_match_info(line: str):
        """
        Возвращает (rule, key) если строка попадает под exclude_endpoints,
        где key - vpn-ключ (прокси-ссылка без комментария).
        """
        s = line.strip()
        if not s or s.startswith("#"):
            return None
        link = s.split(maxsplit=1)[0].strip()
        if "#" in link:
            link = link.split("#", 1)[0].strip()
        parsed = parse_proxy_url(link)
        if not parsed:
            return None
        address = parsed.get("address") or ""
        try:
            port = int(parsed.get("port", 0) or 0)
        except (TypeError, ValueError):
            port = 0
        rule = is_excluded(address, port, exact_endpoints, hosts_only)
        if rule is None:
            return None
        return rule, link

    total_sources_with_matches = 0
    total = len(urls)

    for idx, url in enumerate(urls, start=1):
        print(f"[{idx}/{total}] загрузка {url} ...", flush=True)
        try:
            text = fetch_list(url)
        except Exception as e:
            print(f"[{idx}/{total}] {url} -> ошибка загрузки: {e}")
            continue

        matches = 0
        for line_no, raw_line in enumerate(text.splitlines(), start=1):
            info = extract_match_info(raw_line)
            if info is not None:
                rule, key = info
                matches += 1
                if detailed:
                    print(
                        f"  match: source_idx={idx} url={url} line_in_source={line_no} key={key} rule={rule}"
                    )

        if matches > 0:
            print(f"[{idx}/{total}] {url} -> совпадений по exclude_endpoints: {matches}")
            total_sources_with_matches += 1

    if total_sources_with_matches == 0:
        print("Совпадений по exclude_endpoints ни в одном источнике из links.txt не найдено.")
    else:
        print()
        print(f"Итого источников с совпадениями: {total_sources_with_matches} из {len(urls)}")


if __name__ == "__main__":
    main()

