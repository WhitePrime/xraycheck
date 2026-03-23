#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Фильтр конфигов: исключает строки, у которых endpoint (host:port или host) совпадает со списком.
Список исключений задаётся переменной окружения EXCLUDE_ENDPOINTS (построчно) или файлом
(EXCLUDE_ENDPOINTS_FILE). Приоритет: EXCLUDE_ENDPOINTS, затем файл.
Формат: одна запись на строку - «host:port» или «host» (исключить любой порт). IPv6: [::1]:443.
Пустые строки и строки, начинающиеся с #, игнорируются.

Использование:
  python -m lib.filter_excluded_endpoints [входной_файл]
  EXCLUDE_ENDPOINTS="example.com:443" python -m lib.filter_excluded_endpoints configs/merged_xray.txt
Без аргумента - stdin. Результат - stdout или файл UTF-8 (-o), как у lib.filter_docker_configs
(на Windows перенаправление `> файл` может портить комментарии к URL с эмодзи).
"""

import argparse
import os
import sys
from typing import TextIO


def _configure_stdio_utf8() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconf = getattr(stream, "reconfigure", None)
        if reconf is None:
            continue
        try:
            reconf(encoding="utf-8")
        except (OSError, ValueError, AttributeError, TypeError):
            pass


def _safe_write(out: TextIO, text: str) -> None:
    """
    Безопасная запись в stdout: учитывает, что в Windows консоль/redirect
    могут быть в однобайтовой кодировке (cp1251 и т.п.).
    """
    try:
        out.write(text)
    except UnicodeEncodeError:
        # Пишем в байтовый буфер в utf-8, заменяя неподдерживаемые символы
        out.buffer.write(text.encode("utf-8", errors="replace"))


def _normalize_host(h: str) -> str:
    """Домены сравниваем без учёта регистра, IP - как есть."""
    s = (h or "").strip()
    if not s:
        return s
    # Числовой IP оставляем как есть; иначе приводим к нижнему регистру
    if s.replace(".", "").replace(":", "").isdigit() or (
        ":" in s and s.split(":")[0].replace(".", "").isdigit()
    ):
        return s
    return s.lower()


def _parse_exclude_lines(lines: list[str]) -> tuple[set[str], set[str]]:
    """
    Парсит список строк в (exact_endpoints, hosts_only).
    exact_endpoints: множество "host:port". hosts_only: множество "host" (любой порт).
    """
    exact_endpoints: set[str] = set()
    hosts_only: set[str] = set()
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("[") and "]:" in s:
            idx = s.index("]:")
            host_part = s[1:idx]
            port_part = s[idx + 2 :].strip()
        elif ":" in s:
            host_part, _, port_part = s.rpartition(":")
            port_part = port_part.strip()
        else:
            host = _normalize_host(s)
            if host:
                hosts_only.add(host)
            continue
        host = _normalize_host(host_part)
        try:
            port = int(port_part)
            if host and port >= 0:
                exact_endpoints.add(f"{host}:{port}")
        except ValueError:
            pass
    return exact_endpoints, hosts_only


def load_exclude_set_from_file(filepath: str) -> tuple[set[str], set[str]]:
    """Читает файл исключений. Возвращает (exact_endpoints, hosts_only)."""
    if not filepath or not os.path.isfile(filepath):
        return set(), set()
    with open(filepath, encoding="utf-8") as f:
        return _parse_exclude_lines(f.readlines())


def is_excluded(
    address: str, port: int, exact_endpoints: set[str], hosts_only: set[str]
) -> str | None:
    """
    Проверяет, попадает ли endpoint (address, port) под исключение.
    Возвращает сработавшее правило ("host:port" или "host") или None.
    """
    if not address:
        return None
    host_norm = _normalize_host(address)
    key_exact = f"{host_norm}:{port}"
    if key_exact in exact_endpoints:
        return key_exact
    if host_norm in hosts_only:
        return host_norm
    return None


def main() -> None:
    ap = argparse.ArgumentParser(description="Фильтр: исключить endpoint-ы по списку.")
    ap.add_argument(
        "infile",
        nargs="?",
        help="Файл со строками конфигов. Без аргумента - stdin.",
    )
    ap.add_argument(
        "-o",
        "--output",
        metavar="PATH",
        help="Писать результат в UTF-8 (надёжно на Windows; иначе - stdout).",
    )
    args = ap.parse_args()
    _configure_stdio_utf8()

    # Приоритет: переменная EXCLUDE_ENDPOINTS (построчно), иначе файл EXCLUDE_ENDPOINTS_FILE
    var_content = (os.environ.get("EXCLUDE_ENDPOINTS") or "").strip()
    if var_content:
        exact_endpoints, hosts_only = _parse_exclude_lines(var_content.splitlines())
        filter_source = "переменная EXCLUDE_ENDPOINTS"
    else:
        filepath = os.environ.get("EXCLUDE_ENDPOINTS_FILE", "configs/exclude_endpoints").strip()
        exact_endpoints, hosts_only = load_exclude_set_from_file(filepath)
        filter_source = f"файл {filepath}" if filepath else "не задан"

    source_name = args.infile or "stdin"
    out_sink: TextIO | None = None

    def _emit(out_line: str) -> None:
        payload = out_line if out_line.endswith("\n") else out_line + "\n"
        if out_sink is not None:
            out_sink.write(payload)
        else:
            _safe_write(sys.stdout, payload)

    try:
        if args.output:
            out_sink = open(args.output, "w", encoding="utf-8", newline="\n")

        if not exact_endpoints and not hosts_only:
            # Нет списка или файл пуст - пропускаем все строки без фильтрации
            if args.infile:
                with open(args.infile, encoding="utf-8") as f:
                    for line in f:
                        _emit(line)
            else:
                for line in sys.stdin:
                    _emit(line)
            return

        # Управляет подробным логированием по каждой исключённой строке
        detailed_log = (os.environ.get("EXCLUDE_ENDPOINTS_LOG_DETAILS") or "").strip().lower() in (
            "1",
            "true",
            "yes",
            "on",
        )

        if args.infile:
            with open(args.infile, encoding="utf-8") as f:
                lines = f.readlines()
        else:
            lines = sys.stdin.readlines()

        # Важно: чтобы `import lib.*` работал корректно, добавляем в sys.path НЕ сам `lib/`,
        # а корень проекта (родитель директории `lib`).
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
        from lib.parsing import parse_proxy_url

        excluded_count = 0
        by_rule: dict[str, int] = {}

        for idx, line in enumerate(lines, start=1):
            s = line.rstrip("\n\r")
            if not s.strip() or s.lstrip().startswith("#"):
                _emit(line)
                continue
            link = s.split(maxsplit=1)[0].strip()
            if "#" in link:
                link = link.split("#", 1)[0].strip()
            parsed = parse_proxy_url(link)
            if not parsed:
                _emit(line)
                continue
            address = parsed.get("address") or ""
            try:
                port = int(parsed.get("port", 0) or 0)
            except (TypeError, ValueError):
                port = 0
            matched_rule = is_excluded(address, port, exact_endpoints, hosts_only)
            if matched_rule is not None:
                excluded_count += 1
                by_rule[matched_rule] = by_rule.get(matched_rule, 0) + 1
                if detailed_log:
                    _safe_write(
                        sys.stderr,
                        f"filter_excluded_endpoints match: source={source_name} line={idx} rule={matched_rule} link={link}\n",
                    )
                continue
            _emit(line)

        if excluded_count:
            parts = [
                f"filter_excluded_endpoints: исключено {excluded_count} строк",
                f"фильтр: {filter_source}",
            ]
            if by_rule:
                rules_str = ", ".join(f"{rule} - {by_rule[rule]}" for rule in sorted(by_rule))
                parts.append(f"по правилам: {rules_str}")
            _safe_write(sys.stderr, " | ".join(parts) + "\n")
    finally:
        if out_sink is not None:
            out_sink.close()


if __name__ == "__main__":
    main()
