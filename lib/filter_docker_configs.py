#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Фильтр конфигов перед проверкой в Docker: для распознанных proxy-URL оставляет строки,
у которых
1) IP endpoint (адрес после @) попадает в одну из подсетей из cidrlist (корень репо);
2) по умолчанию: параметр SNI совпадает с одной из строк в файле sni (корень репо),
   без учёта регистра, после trim.
   Режим только CIDR (--cidr-only или FILTER_DOCKER_CIDR_ONLY=1): пункт 2 не применяется.

Адрес в конфиге не меняется: в вывод (stdout или -o) уходит исходная строка целиком.

Если вместо литерала указан домен или поддомен, по нему выполняется DNS (A/AAAA,
короткий таймаут). Для проверки CIDR берутся все полученные адреса; достаточно,
чтобы хотя бы один из них входил в cidrlist. Если резолв не удался - строка
отбрасывается.

Использование:
  python -m lib.filter_docker_configs [входной_файл]
  cat configs/available | python -m lib.filter_docker_configs

Пути к cidrlist и sni по умолчанию: <корень_проекта>/cidrlist и <корень_проекта>/sni
(корень - родитель каталога lib). Переопределение:
  --cidrlist PATH --sni PATH

Результат - stdout (или файл с -o): пустые строки, строки-комментарии (# в начале
после пробелов) и строки без распознаваемого proxy-URL передаются без изменений;
фрагмент после # внутри URL (подпись к ключу) не трогается. Остальные строки
фильтруются по правилам выше. Сводка - stderr.

На Windows перенаправление shell-а (`> файл`) может испортить не-ASCII в комментариях
к URL: используйте -o/--output (запись в UTF-8) или PYTHONIOENCODING=utf-8.

Переменные окружения:
  FILTER_DOCKER_VERBOSE=1 - в stderr причину отбрасывания каждой строки.
  FILTER_DOCKER_CIDR_ONLY=1 - только проверка CIDR (как --cidr-only), без sni.

В GitHub Actions (daily-check-docker.yml) в env workflow заданы FILTER_DOCKER_CONFIGS_ENABLED=true
и FILTER_DOCKER_CIDR_ONLY=1 (отсев только по CIDR). Отсев включается при true / 1 / yes для
FILTER_DOCKER_CONFIGS_ENABLED; при false / 0 / no шаг не вызывает скрипт, configs/available не меняется.
Локально при явном запуске python -m lib.filter_docker_configs отсев выполняется всегда (без
FILTER_DOCKER_CIDR_ONLY по умолчанию проверяется и sni).
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import socket
import sys
from typing import TextIO


def _project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _configure_stdio_utf8() -> None:
    """Снижает риск порчи эмодзи/UTF-8 в комментариях при выводе в pipe/файл (Windows)."""
    for stream in (sys.stdout, sys.stderr):
        reconf = getattr(stream, "reconfigure", None)
        if reconf is None:
            continue
        try:
            reconf(encoding="utf-8")
        except (OSError, ValueError, AttributeError, TypeError):
            pass


def _safe_write(out: TextIO, text: str) -> None:
    try:
        out.write(text)
    except UnicodeEncodeError:
        out.buffer.write(text.encode("utf-8", errors="replace"))


def _safe_err(text: str) -> None:
    _safe_write(sys.stderr, text)


def load_cidr_networks(path: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    if not path or not os.path.isfile(path):
        return nets
    with open(path, encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            try:
                nets.append(ipaddress.ip_network(s, strict=False))
            except ValueError:
                continue
    return nets


def load_sni_set(path: str) -> set[str]:
    if not path or not os.path.isfile(path):
        return set()
    seen: set[str] = set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            seen.add(s.casefold())
    return seen


def _resolve_endpoint_ips(address: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """
    Литерал IPv4/IPv6 из конфига - один адрес. Имя хоста (домен/поддомен) -
    DNS: все уникальные A/AAAA, порядок: сначала v4, затем v6.
    """
    if not address:
        return []
    literal = address.strip()
    if literal.startswith("[") and literal.endswith("]"):
        literal = literal[1:-1].strip()
    try:
        return [ipaddress.ip_address(literal)]
    except ValueError:
        pass
    # literal уже без [ ] для bracket-form; для DNS не использовать исходный address со скобками
    host_for_dns = literal
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(3.0)
    try:
        infos = socket.getaddrinfo(
            host_for_dns, None, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
    except OSError:
        return []
    finally:
        socket.setdefaulttimeout(old_timeout)

    v4: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    v6: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    seen: set[str] = set()
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        ip_str = sockaddr[0]
        if ip_str in seen:
            continue
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        seen.add(ip_str)
        if ip_obj.version == 4:
            v4.append(ip_obj)
        else:
            v6.append(ip_obj)
    return v4 + v6


def _sni_from_parsed(parsed: dict) -> str:
    proto = parsed.get("protocol") or ""
    if proto == "hysteria":
        return (parsed.get("peer") or "").strip()
    if proto == "hysteria2":
        return (parsed.get("sni") or "").strip()
    if proto == "shadowsocks":
        return ""
    return (parsed.get("serverName") or "").strip()


def _ip_in_networks(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> bool:
    for net in networks:
        if ip.version != net.version:
            continue
        if ip in net:
            return True
    return False


def filter_line(
    parsed: dict | None,
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
    sni_ok: set[str],
    *,
    cidr_only: bool = False,
) -> tuple[bool, str]:
    """
    Возвращает (оставить_строку_в_выводе, причина_отказа_для_verbose).
    """
    if not parsed:
        return False, "не удалось распарсить URL"
    addr = (parsed.get("address") or "").strip()
    if not addr:
        return False, "пустой address"
    if not cidr_only:
        sni = _sni_from_parsed(parsed)
        if not sni:
            return False, "нет SNI (или неподдерживаемый протокол без SNI)"
        if sni.casefold() not in sni_ok:
            return False, f"SNI не в списке sni: {sni!r}"
    ips = _resolve_endpoint_ips(addr)
    if not ips:
        return False, f"не удалось разрешить host в IP (DNS): {addr!r}"
    if not networks:
        return False, "cidrlist пуст или не загружен"
    if not any(_ip_in_networks(ip, networks) for ip in ips):
        shown = ", ".join(str(x) for x in ips[:8])
        if len(ips) > 8:
            shown += f", … (+{len(ips) - 8})"
        return False, f"ни один из IP endpoint не в cidrlist ({shown})"
    return True, ""


def main() -> None:
    root = _project_root()
    ap = argparse.ArgumentParser(
        description="Фильтр configs для Docker: по умолчанию cidrlist + sni; "
        "режим только CIDR - флаг --cidr-only или FILTER_DOCKER_CIDR_ONLY=1."
    )
    ap.add_argument(
        "infile",
        nargs="?",
        help="Файл со строками конфигов (как configs/available). Без аргумента - stdin.",
    )
    ap.add_argument(
        "--cidrlist",
        default=os.path.join(root, "cidrlist"),
        help="Файл с CIDR (по умолчанию: <repo>/cidrlist)",
    )
    ap.add_argument(
        "--cidr-only",
        action="store_true",
        help="Проверять только попадание endpoint в CIDR; sni не загружается и не учитывается.",
    )
    ap.add_argument(
        "--sni",
        default=os.path.join(root, "sni"),
        help="Файл со списком допустимых SNI (по умолчанию: <repo>/sni; игнорируется с --cidr-only)",
    )
    ap.add_argument(
        "-o",
        "--output",
        metavar="PATH",
        help="Писать отфильтрованный список в файл в UTF-8 (надёжно на Windows; иначе - stdout).",
    )
    args = ap.parse_args()
    _configure_stdio_utf8()

    verbose = (os.environ.get("FILTER_DOCKER_VERBOSE") or "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )
    cidr_only = args.cidr_only or (
        (os.environ.get("FILTER_DOCKER_CIDR_ONLY") or "").strip().lower()
        in ("1", "true", "yes", "on")
    )

    if args.infile:
        source_name = args.infile
        with open(args.infile, encoding="utf-8") as inf:
            lines = inf.readlines()
    else:
        source_name = "stdin"
        lines = sys.stdin.readlines()

    project_root = root
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    from lib.parsing import parse_proxy_url

    networks = load_cidr_networks(args.cidrlist)
    sni_ok = set() if cidr_only else load_sni_set(args.sni)

    kept = 0
    dropped = 0
    reasons: dict[str, int] = {}

    out_sink: TextIO | None = None
    try:
        if args.output:
            out_sink = open(args.output, "w", encoding="utf-8", newline="\n")

        def _emit_line(out_line: str) -> None:
            payload = out_line if out_line.endswith("\n") else out_line + "\n"
            if out_sink is not None:
                out_sink.write(payload)
            else:
                _safe_write(sys.stdout, payload)

        for idx, line in enumerate(lines, start=1):
            s = line.rstrip("\n\r")
            if not s.strip() or s.lstrip().startswith("#"):
                _emit_line(line)
                continue
            link = s.split(maxsplit=1)[0].strip()
            if "#" in link:
                link = link.split("#", 1)[0].strip()
            parsed = parse_proxy_url(link)
            if not parsed:
                _emit_line(line)
                continue
            ok, reason = filter_line(parsed, networks, sni_ok, cidr_only=cidr_only)
            if ok:
                kept += 1
                _emit_line(line)
            else:
                dropped += 1
                reasons[reason] = reasons.get(reason, 0) + 1
                if verbose:
                    _safe_err(
                        f"filter_docker_configs: skip {source_name}:{idx} {reason} link={link[:120]}\n"
                    )

        parts = [
            f"filter_docker_configs: оставлено {kept}, отброшено {dropped}",
            f"cidrlist={args.cidrlist} ({len(networks)} подсетей)",
        ]
        if cidr_only:
            parts.append("режим: только CIDR")
        else:
            parts.append(f"sni={args.sni} ({len(sni_ok)} уникальных SNI)")
        if dropped and reasons and not verbose:
            top = sorted(reasons.items(), key=lambda x: -x[1])[:5]
            parts.append("топ причин: " + "; ".join(f"{r} ({n})" for r, n in top))
        _safe_err(" | ".join(parts) + "\n")
    finally:
        if out_sink is not None:
            out_sink.close()


if __name__ == "__main__":
    main()
