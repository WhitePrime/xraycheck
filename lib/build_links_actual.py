#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Единый сборщик "актуальных" источников по фильтру CIDR.

По каждому URL из `linksnew.txt`:
1) скачивает список конфигов (включая base64-подписки);
2) считает общее число строк-конфигов (как в check_links.py: непустые строки);
3) считает, сколько конфигов проходит фильтр lib.filter_docker_configs.py в режиме `--cidr-only`;
4) получает дату обновления источника так же, как в lib.check_links.py:
   - для raw.githubusercontent.com: дата последнего коммита через GitHub API;
   - для остальных: Last-Modified / Date из HTTP-заголовков.

Результат запуска: четыре файла:
 - links_actual_ru.txt: источники, где >0 конфигов прошло filter (--cidr-only),
   отсортировано по количеству прошедших конфигов (по убыванию).
 - links_actual_other.txt: остальные источники.
 - links_actual_lost.txt: источники с 0 конфигами или ошибкой загрузки.
 - docs/links_actual_report.md: таблица со статистикой по каждому источнику.
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass
from typing import Iterable


def _project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _safe_int(x: object, default: int = 0) -> int:
    try:
        return int(x)  # type: ignore[arg-type]
    except Exception:
        return default


def _count_nonempty_lines(text: str) -> int:
    # В check_links.py используется len([l for l in text.splitlines() if l.strip()])
    return sum(1 for l in text.splitlines() if l.strip())


def _normalize_source_urls(urls: Iterable[str]) -> list[str]:
    # Как в check_links.py: dedup preserving order
    out: list[str] = []
    seen: set[str] = set()
    for u in urls:
        u = (u or "").strip()
        if not u or u.startswith("#"):
            continue
        if u in seen:
            continue
        seen.add(u)
        out.append(u)
    return out


@dataclass(frozen=True)
class SourceStats:
    url: str
    total_configs: int
    passed_configs: int
    updated_date: str


def _load_sources(links_file: str) -> list[str]:
    with open(links_file, "r", encoding="utf-8") as f:
        # Разрешаем "URL #comment" и строки с мусором
        urls = [line.strip().split("#", 1)[0].strip() for line in f if line.strip()]
    return _normalize_source_urls(urls)


def _should_use_github_commit_date(url: str) -> tuple[bool, tuple[str, str, str, str] | None]:
    """
    Возвращает (True, (owner, repo, ref, path)) для raw.githubusercontent.com и GitHub raw-паттернов,
    которые поддерживает parse_github_raw в lib.check_links.py.
    """
    from lib.check_links import parse_github_raw

    gh = parse_github_raw(url)
    return (gh is not None, gh)


def _github_commit_date(owner: str, repo: str, ref: str, path: str) -> str:
    from lib.check_links import github_file_date

    token = os.environ.get("GITHUB_TOKEN")
    return github_file_date(owner=owner, repo=repo, ref=ref, path=path, token=token)


def _fetch_text_and_header_date(url: str) -> tuple[str, str]:
    """
    Возвращает (decoded_text, header_date YYYY-MM-DD или строка как в parsing.fetch_list_with_meta).
    """
    from lib.parsing import fetch_list_with_meta

    return fetch_list_with_meta(url)


def _cidr_passed_count_for_text(
    text: str,
    *,
    networks: list,
) -> int:
    """
    Считает, сколько строк-конфигов проходит filter_docker_configs.py в режиме cidr-only.
    Важно: считаем только "kept" строки, которые фильтр реально распознал как proxy URL.
    """
    from lib.filter_docker_configs import filter_line
    from lib.parsing import parse_proxy_url

    passed = 0
    # В режиме cidr-only sni не учитывается, но filter_line требует sni_ok параметр.
    sni_ok: set[str] = set()

    for line in text.splitlines():
        s = line.rstrip("\n\r")
        if not s.strip() or s.lstrip().startswith("#"):
            continue

        link = s.split(maxsplit=1)[0].strip()
        if "#" in link:
            link = link.split("#", 1)[0].strip()
        if not link:
            continue

        parsed = parse_proxy_url(link)
        if not parsed:
            continue

        ok, _reason = filter_line(parsed, networks, sni_ok, cidr_only=True)
        if ok:
            passed += 1
    return passed


def _write_lines(path: str, lines: list[str]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for l in lines:
            f.write(l.rstrip("\n\r") + "\n")


def _write_report_md(
    path: str,
    *,
    cidrlist_path: str,
    filter_mode: str,
    total_sources: int,
    ru_sources: list[SourceStats],
    other_sources: list[SourceStats],
    lost_sources: list[SourceStats],
) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    updated_at = __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    ru_total_configs = sum(s.total_configs for s in ru_sources)
    ru_total_passed = sum(s.passed_configs for s in ru_sources)

    def fmt_cell(x: str | int) -> str:
        # Markdown table escape
        return str(x).replace("|", "\\|")

    lines: list[str] = []
    lines.append(f"# links_actual report ({filter_mode})")
    lines.append("")
    lines.append(f"- `cidrlist`: `{cidrlist_path}`")
    lines.append(f"- `run datetime`: {updated_at}")
    lines.append("")
    lines.append(f"Всего источников: **{total_sources}**")
    lines.append(
        f"Источники с прошедшими конфигами (>0): **{len(ru_sources)}** "
        f"(всего конфигов: {ru_total_configs}, прошли фильтр: {ru_total_passed})"
    )
    lines.append("")

    def add_section(title: str, stats: list[SourceStats]) -> None:
        lines.append(f"## {title}")
        lines.append("")
        lines.append("| Источник | Всего конфигов | Прошли CIDR | Дата обновления |")
        lines.append("|---|---:|---:|---|")
        for s in stats:
            # Ссылка в markdown не ломает столбцы (URL содержит без |)
            url_md = f"[link]({s.url})"
            lines.append(
                "| "
                + fmt_cell(url_md)
                + " | "
                + fmt_cell(s.total_configs)
                + " | "
                + fmt_cell(s.passed_configs)
                + " | "
                + fmt_cell(s.updated_date)
                + " |"
            )
        lines.append("")

    add_section("RU (passed > 0)", ru_sources)
    add_section("OTHER (passed = 0 / total > 0)", other_sources)
    add_section("LOST (0 configs or fetch error)", lost_sources)

    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines).rstrip() + "\n")


def main() -> None:
    ap = argparse.ArgumentParser(description="Build links_actual_* and markdown report by --cidr-only.")
    ap.add_argument("--links-file", default=None, help="linksnew.txt (по умолчанию: <repo>/linksnew.txt)")
    ap.add_argument("--cidrlist", default=None, help="Путь к cidrlist (по умолчанию: <repo>/cidrlist)")
    ap.add_argument("--out-ru", default="links_actual_ru.txt", help="Файл со списком RU-источников")
    ap.add_argument("--out-other", default="links_actual_other.txt", help="Файл со списком OTHER-источников")
    ap.add_argument("--out-lost", default="links_actual_lost.txt", help="Файл со списком LOST-источников")
    ap.add_argument(
        "--out-md",
        default=os.path.join("docs", "links_actual_report.md"),
        help="MD-отчёт в папке docs",
    )
    ap.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Ограничение количества источников для теста (0 = без ограничений)",
    )
    args = ap.parse_args()

    root = _project_root()
    links_file = args.links_file or os.path.join(root, "linksnew.txt")
    cidrlist_path = args.cidrlist or os.path.join(root, "cidrlist")
    out_ru = os.path.join(root, args.out_ru)
    out_other = os.path.join(root, args.out_other)
    out_lost = os.path.join(root, args.out_lost)
    out_md = os.path.join(root, args.out_md)

    if not os.path.isfile(links_file):
        raise FileNotFoundError(f"Не найден файл источников: {links_file}")
    if not os.path.isfile(cidrlist_path):
        raise FileNotFoundError(f"Не найден cidrlist: {cidrlist_path}")

    # Импортируем здесь, чтобы sys.path была корректной при запуске из любой директории
    if root not in sys.path:
        sys.path.insert(0, root)

    from lib.filter_docker_configs import load_cidr_networks

    networks = load_cidr_networks(cidrlist_path)
    if not networks:
        print("Warning: cidrlist пуст или не загружен, фильтр может отбрасывать все IP-эндпоинты.", file=sys.stderr)

    sources = _load_sources(links_file)
    if args.limit and args.limit > 0:
        sources = sources[: args.limit]

    print(f"Sources to process: {len(sources)}", file=sys.stderr)

    stats: list[SourceStats] = []
    from lib.check_links import parse_github_raw  # reuse for speed

    for idx, url in enumerate(sources, start=1):
        try:
            text, header_date = _fetch_text_and_header_date(url)
            total_configs = _count_nonempty_lines(text)

            passed_configs = _cidr_passed_count_for_text(text, networks=networks)

            # Дата: для GitHub raw берём commit date как в check_links.py
            updated_date = header_date or "-"
            gh = parse_github_raw(url)
            if gh:
                owner, repo, ref, path = gh
                commit_date = _github_commit_date(owner=owner, repo=repo, ref=ref, path=path)
                if commit_date and not commit_date.startswith("error:"):
                    updated_date = commit_date

        except Exception as e:
            # На практике часть источников может быть недоступна / отдавать нестандартный контент.
            # По требованию - такие источники уйдут в OTHER.
            total_configs = 0
            passed_configs = 0
            updated_date = f"error: {type(e).__name__}"

        stats.append(
            SourceStats(
                url=url,
                total_configs=total_configs,
                passed_configs=passed_configs,
                updated_date=updated_date,
            )
        )

        if idx % 10 == 0 or idx == len(sources):
            print(f"[{idx}/{len(sources)}] processed: {url} (passed={passed_configs})", file=sys.stderr)

    def _is_lost(s: SourceStats) -> bool:
        # LOST: 0 конфигов или ошибка загрузки
        return s.total_configs <= 0 or (s.updated_date or "").startswith("error:")

    ru_sources = [s for s in stats if s.passed_configs > 0]
    lost_sources = [s for s in stats if _is_lost(s) and s.passed_configs <= 0]
    other_sources = [
        s for s in stats if (s.passed_configs <= 0) and (not _is_lost(s))
    ]

    # Топы по количеству прошедших конфигов.
    ru_sources_sorted = sorted(
        ru_sources,
        key=lambda s: (s.passed_configs, s.total_configs, s.url),
        reverse=True,
    )

    other_sources_sorted = other_sources[:]  # keep original order
    lost_sources_sorted = lost_sources[:]  # keep original order

    _write_lines(out_ru, [s.url for s in ru_sources_sorted])
    _write_lines(out_other, [s.url for s in other_sources_sorted])
    _write_lines(out_lost, [s.url for s in lost_sources_sorted])

    _write_report_md(
        out_md,
        cidrlist_path=cidrlist_path,
        filter_mode="--cidr-only",
        total_sources=len(stats),
        ru_sources=ru_sources_sorted,
        other_sources=other_sources_sorted,
        lost_sources=lost_sources_sorted,
    )

    print(f"Written: {out_ru}", file=sys.stderr)
    print(f"Written: {out_other}", file=sys.stderr)
    print(f"Written: {out_lost}", file=sys.stderr)
    print(f"Written: {out_md}", file=sys.stderr)


if __name__ == "__main__":
    main()

