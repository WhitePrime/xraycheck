#!/usr/bin/env python3
"""
Entrypoint для Docker: ограничивает исходящий доступ контейнера только
CIDR из whitelist (CIDR_WHITELIST_URL). IP прокси в разрешённые не добавляются.
"""
import ipaddress
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

try:
    from lib.parsing import normalize_proxy_link as _norm_link_entrypoint
except ImportError:
    _norm_link_entrypoint = None

CIDR_WHITELIST_URL = os.environ.get(
    "CIDR_WHITELIST_URL",
    "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/cidrwhitelist.txt",
)
LINKS_FILE = os.environ.get("LINKS_FILE", "links.txt")


def fetch(url: str) -> str:
    # Валидация URL перед использованием
    try:
        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Некорректный URL: {url}")
        # Проверка на управляющие символы
        if any(ord(c) < 32 and c not in '\t\n\r' for c in url):
            raise ValueError(f"URL содержит управляющие символы: {url}")
    except Exception as e:
        raise ValueError(f"Ошибка валидации URL: {e}")
    
    with urllib.request.urlopen(url, timeout=30) as r:
        return r.read().decode("utf-8", errors="replace")


def parse_vless_lines(text: str) -> list[tuple[str, str]]:
    """Строки с прокси-протоколами: (ссылка, полная_строка). Поддерживает VLESS, VMess, Trojan, Shadowsocks."""
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


def merge_keys_from_urls(urls: list[str]) -> str:
    """Загружает списки по каждому URL, объединяет ключи (дедупликация по ссылке), возвращает текст."""
    seen: set[str] = set()
    lines: list[str] = []
    total = len(urls)
    print("\n=== docker (entrypoint): загрузка списка по URL ===")
    print(f"[1] Режим merge: объединение ключей из {total} ссылок (links.txt):")
    for idx, url in enumerate(urls, 1):
        try:
            text = fetch(url)
            parsed = parse_vless_lines(text)
            new_count = 0
            for link, full in parsed:
                if link not in seen:
                    seen.add(link)
                    lines.append(full)
                    new_count += 1
            print(f"     [{idx}/{total}] получено {len(parsed)}, новых +{new_count}, всего уникальных: {len(lines)}")
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError) as e:
            error_msg = str(e)
            if len(error_msg) > 100:
                error_msg = error_msg[:97] + "..."
            print(f"     [{idx}/{total}] Ошибка загрузки: {error_msg} (пропущено)", file=sys.stderr)
            continue
    print(f"[1] Итого из ссылок: {len(lines)} уникальных ключей (по ссылке)")
    print("=== конец загрузки ===\n")
    return "\n".join(lines)


def parse_cidr_whitelist(text: str) -> set[str]:
    """Парсит список CIDR/IP: по одной записи на строку. Возвращает множество строк 'ip' или 'ip/cidr'."""
    result = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Одна запись на строку: 1.2.3.4 или 1.2.3.4/24
        entry = line.split()[0] if line.split() else line
        try:
            if "/" in entry:
                ipaddress.ip_network(entry, strict=False)
                result.add(entry)
            else:
                ipaddress.ip_address(entry)
                result.add(entry)
        except ValueError:
            continue
    return result


HYSTERIA_PREFIXES = ("hysteria://", "hysteria2://", "hy2://")


def split_list_by_protocol(list_path: str) -> tuple[str, str, int, int]:
    """Читает список, разделяет на Xray (VLESS, VMess, Trojan, SS) и Hysteria. Возвращает (path_xray, path_hysteria, n_xray, n_hysteria)."""
    xray_path = "/tmp/xray_list.txt"
    hysteria_path = "/tmp/hysteria_list.txt"
    xray_lines = []
    hyst_lines = []
    with open(list_path, encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            line_endl = line if line.endswith("\n") else line + "\n"
            if s.startswith(HYSTERIA_PREFIXES):
                hyst_lines.append(line_endl)
            else:
                xray_lines.append(line_endl)
    with open(xray_path, "w", encoding="utf-8") as f:
        f.writelines(xray_lines)
    with open(hysteria_path, "w", encoding="utf-8") as f:
        f.writelines(hyst_lines)
    return xray_path, hysteria_path, len(xray_lines), len(hyst_lines)


def setup_iptables(allowed_destinations: set[str]) -> None:
    """Разрешить только исходящие соединения к allowed_destinations (IP или CIDR), localhost и DNS.
    Использует iptables-restore для быстрой загрузки десятков тысяч правил одним вызовом."""
    lines = [
        "*filter",
        ":OUTPUT ACCEPT [0:0]",
        "-F OUTPUT",
        "-P OUTPUT DROP",
        "-A OUTPUT -o lo -j ACCEPT",
        "-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
    ]
    for dns_ip in ("8.8.8.8", "8.8.4.4", "1.1.1.1"):
        lines.append(f"-A OUTPUT -p udp --dport 53 -d {dns_ip} -j ACCEPT")
    for dest in sorted(allowed_destinations):
        if dest:
            lines.append(f"-A OUTPUT -d {dest} -j ACCEPT")
    lines.append("COMMIT")
    script = "\n".join(lines) + "\n"
    proc = subprocess.run(
        ["iptables-restore", "--noflush"],
        input=script.encode(),
        capture_output=True,
        timeout=60,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"iptables-restore failed: {proc.stderr.decode(errors='replace')}")


def main():
    mode = (os.environ.get("MODE", "single") or "single").strip().lower()
    list_url = (
        (sys.argv[1] if len(sys.argv) > 1 and sys.argv[1].startswith("http") else None)
        or os.environ.get("DEFAULT_LIST_URL", "")
    )
    list_file = None
    list_from_stdin = False  # не дедуплицировать - список уже уникален с хоста

    if mode == "merge":
        links_path = LINKS_FILE if os.path.isfile(LINKS_FILE) else os.path.join("/app", LINKS_FILE)
        if not os.path.isfile(links_path):
            print(f"Ошибка: файл со ссылками не найден: {links_path}", file=sys.stderr)
            sys.exit(1)
        with open(links_path, encoding="utf-8") as f:
            urls = []
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
        if not urls:
            print("В файле со ссылками нет URL.", file=sys.stderr)
            sys.exit(1)
        try:
            keys_text = merge_keys_from_urls(urls)
        except Exception as e:
            print(f"Ошибка загрузки списков: {e}", file=sys.stderr)
            sys.exit(1)
        list_file = "/tmp/vless_keys_list.txt"
        with open(list_file, "w", encoding="utf-8") as f:
            f.write(keys_text)
        list_url = list_file
        os.environ["MODE"] = "single"
    elif len(sys.argv) > 1 and sys.argv[1] == "-":
        # Список из stdin (гарантирует передачу всех строк с хоста без потерь при монтировании)
        list_from_stdin = True
        keys_text = sys.stdin.read()
        list_file = "/tmp/vless_keys_list.txt"
        with open(list_file, "w", encoding="utf-8") as f:
            f.write(keys_text)
        n_lines = len([l for l in keys_text.splitlines() if l.strip() and not l.strip().startswith("#")])
        print(f"\n=== docker (entrypoint): загрузка списка из stdin ===")
        print(f"[1] Из stdin: загружено {n_lines} строк (VLESS, VMess, Trojan, SS, Hysteria)")
        print("=== конец загрузки ===\n")
    elif len(sys.argv) > 1 and sys.argv[1] and not sys.argv[1].startswith("http"):
        # Локальный файл со списком (например configs/merged_xray.txt)
        path = sys.argv[1] if os.path.isabs(sys.argv[1]) else os.path.join("/app", sys.argv[1])
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as f:
                keys_text = f.read()
            list_file = "/tmp/vless_keys_list.txt"
            with open(list_file, "w", encoding="utf-8") as f:
                f.write(keys_text)
            n_lines = len([l for l in keys_text.splitlines() if l.strip() and not l.strip().startswith("#")])
            print(f"\n=== docker (entrypoint): загрузка списка из файла ===")
            print(f"[1] Файл {path}: загружено {n_lines} строк (VLESS, VMess, Trojan, SS, Hysteria)")
            print("=== конец загрузки ===\n")
        else:
            print(f"Файл не найден: {path}", file=sys.stderr)
            sys.exit(1)

    if list_file is None:
        if not list_url:
            print("DEFAULT_LIST_URL не задан, пропуск настройки firewall.", file=sys.stderr)
            os.execvp("python", ["python", "vless_checker.py"] + sys.argv[1:])
            return
        print("\n=== docker (entrypoint): загрузка списка по URL ===")
        print("[1] Загрузка списка ключей по URL...")
        try:
            keys_text = fetch(list_url)
        except Exception as e:
            print(f"Ошибка загрузки списка ключей: {e}", file=sys.stderr)
            sys.exit(1)
        n_lines = len([l for l in keys_text.splitlines() if l.strip() and not l.strip().startswith("#")])
        print(f"[1] Загружено по URL: {n_lines} строк")
        print("=== конец загрузки ===\n")
        list_file = "/tmp/vless_keys_list.txt"
        with open(list_file, "w", encoding="utf-8") as f:
            f.write(keys_text)

    # Дедупликация входа по нормализованной ссылке (пропуск при list_from_stdin - список уже уникален с хоста)
    with open(list_file, "r", encoding="utf-8") as f:
        raw_lines = [l.rstrip("\n\r") for l in f if l.strip()]

    if list_from_stdin:
        lines_dedup = raw_lines
        print("\n=== docker (entrypoint): сводка по количеству конфигов ===")
        print(f"[1] Входной список (stdin): {len(raw_lines)} записей (без дедупликации - передано с хоста)")
        print(f"[2] К передаче в проверку: {len(lines_dedup)} записей")
    else:
        def _norm_link(line: str) -> str:
            if _norm_link_entrypoint is not None:
                return _norm_link_entrypoint(line)
            s = line.strip().split(maxsplit=1)[0].strip()
            if "#" in s:
                s = s.split("#", 1)[0].strip()
            return s

        seen_norm = set()
        lines_dedup = []
        for line in raw_lines:
            n = _norm_link(line)
            if n and n not in seen_norm:
                seen_norm.add(n)
                lines_dedup.append(line)
        with open(list_file, "w", encoding="utf-8") as f:
            f.write("\n".join(lines_dedup) + ("\n" if lines_dedup else ""))

        print("\n=== docker (entrypoint): сводка по количеству конфигов ===")
        print(f"[1] Входной список: {len(raw_lines)} записей")
        dup_removed = len(raw_lines) - len(lines_dedup)
        if dup_removed > 0:
            print(f"[2] Дедупликация по нормализованному ключу: {len(raw_lines)} -> {len(lines_dedup)} уникальных (удалено дубликатов: -{dup_removed})")
        else:
            print(f"[2] Дедупликация по нормализованному ключу: дубликатов нет, {len(lines_dedup)} записей")

    print("Загрузка CIDR whitelist...")
    try:
        cidr_text = fetch(CIDR_WHITELIST_URL)
    except Exception as e:
        print(f"Ошибка загрузки CIDR whitelist: {e}", file=sys.stderr)
        sys.exit(1)
    cidr_entries = parse_cidr_whitelist(cidr_text)
    print(f"Записей CIDR в белом списке: {len(cidr_entries)}")

    allowed_destinations = cidr_entries
    print(f"Разрешённых назначений (только CIDR whitelist): {len(allowed_destinations)}")

    print("Применение iptables (только CIDR whitelist)...")
    try:
        setup_iptables(allowed_destinations)
    except Exception as e:
        print(f"Ошибка iptables (нужен cap NET_ADMIN): {e}", file=sys.stderr)
        sys.exit(1)

    # Разделяем список на Xray и Hysteria; для Hysteria используем hysteria_checker.py и speedtest_hysteria.py
    xray_list, hysteria_list, n_xray, n_hysteria = split_list_by_protocol(list_file)
    n_total = n_xray + n_hysteria
    print(f"[3] Разделение по протоколам: {len(lines_dedup)} ключей -> Xray {n_xray}, Hysteria {n_hysteria}")
    if n_total < len(lines_dedup):
        print(f"[!] Внимание: {len(lines_dedup) - n_total} строк не распознаны как Xray или Hysteria (пустые/комментарии уже исключены)")
    print(f"    Всего к проверке: {n_total} (vless_checker: {n_xray}, hysteria_checker: {n_hysteria})")
    print("=== конец сводки ===\n")
    configs_dir = os.path.join("/app", "configs")
    os.makedirs(configs_dir, exist_ok=True)
    wl_path = os.path.join(configs_dir, "white-list_available")

    # 1) vless_checker только по Xray-списку -> configs/white-list_available
    # Строгие значения по умолчанию для проверки (как в мобильных клиентах), чтобы меньше ложных «рабочих» ключей
    for key, val in (
        ("STRONG_STYLE_TEST", "true"),
        ("REQUIRE_HTTPS", "true"),
        ("STRICT_MODE", "true"),
        ("STRICT_MODE_REQUIRE_ALL", "true"),
        ("STRONG_ATTEMPTS", "3"),
        ("STRONG_STYLE_TIMEOUT", "12"),
        ("STRONG_MAX_RESPONSE_TIME", "3"),
        ("TEST_URLS_HTTPS", "https://www.gstatic.com/generate_204"),
        ("MIN_SUCCESSFUL_REQUESTS", "2"),
        ("MIN_SUCCESSFUL_URLS", "2"),
        ("STABILITY_CHECKS", "2"),
    ):
        os.environ.setdefault(key, val)

    if os.path.getsize(xray_list) > 0:
        print("Запуск vless_checker.py (Xray: VLESS, VMess, Trojan, SS)...")
        script_args = ["python", "vless_checker.py", xray_list]
        for a in sys.argv[2:]:
            if a.startswith("-"):
                script_args.append(a)
        ret = subprocess.run(script_args)
        if ret.returncode != 0:
            sys.exit(ret.returncode)
    else:
        with open(wl_path, "w", encoding="utf-8") as f:
            pass

    # 2) hysteria_checker по Hysteria-списку -> configs/hysteria
    if os.path.getsize(hysteria_list) > 0:
        print("Запуск hysteria_checker.py (Hysteria)...")
        ret_h = subprocess.run(["python", "hysteria_checker.py", hysteria_list], env=os.environ)
        if ret_h.returncode != 0:
            print("hysteria_checker завершился с ошибкой, продолжаем без Hysteria.", file=sys.stderr)

    # 3) Speedtest по Xray (white-list_available)
    speedtest_enabled = os.environ.get("SPEED_TEST_ENABLED", "").strip().lower() in ("true", "1", "yes")
    xray_st_path = os.path.join(configs_dir, "white-list_available_st")
    if speedtest_enabled and os.path.isfile(wl_path) and os.path.getsize(wl_path) > 0:
        print("Запуск speedtest_checker.py по white-list_available (Xray)...")
        ret2 = subprocess.run(["python", "speedtest_checker.py", wl_path], env=os.environ)
        if ret2.returncode == 0 and os.path.isfile(xray_st_path) and os.path.getsize(xray_st_path) > 0:
            with open(xray_st_path, "r", encoding="utf-8") as f:
                xray_content = f.read()
        else:
            with open(wl_path, "r", encoding="utf-8") as f:
                xray_content = f.read()
    else:
        xray_content = ""
        if os.path.isfile(wl_path):
            with open(wl_path, "r", encoding="utf-8") as f:
                xray_content = f.read()

    # 4) Speedtest по Hysteria (configs/hysteria -> configs/hysteria_st)
    hysteria_path = os.path.join(configs_dir, "hysteria")
    hysteria_st_path = os.path.join(configs_dir, "hysteria_st")
    hysteria_content = ""
    if speedtest_enabled and os.path.isfile(hysteria_path) and os.path.getsize(hysteria_path) > 0:
        print("Запуск speedtest_hysteria.py по configs/hysteria...")
        ret3 = subprocess.run(["python", "speedtest_hysteria.py", hysteria_path], env=os.environ)
        if ret3.returncode == 0 and os.path.isfile(hysteria_st_path) and os.path.getsize(hysteria_st_path) > 0:
            with open(hysteria_st_path, "r", encoding="utf-8") as f:
                hysteria_content = f.read()
        else:
            with open(hysteria_path, "r", encoding="utf-8") as f:
                hysteria_content = f.read()
    elif os.path.isfile(hysteria_path) and os.path.getsize(hysteria_path) > 0:
        with open(hysteria_path, "r", encoding="utf-8") as f:
            hysteria_content = f.read()

    # 5) Слияние Xray + Hysteria в white-list_available и top100; дедупликация по нормализованной ссылке (без #)
    merged = (xray_content.rstrip() + "\n" + hysteria_content).strip() if hysteria_content else xray_content.strip()
    raw_lines = [l for l in merged.splitlines() if l.strip()]

    def _norm_link(line: str) -> str:
        s = line.strip().split(maxsplit=1)[0].strip()
        if "#" in s:
            s = s.split("#", 1)[0].strip()
        return s

    seen_norm = set()
    lines = []
    for line in raw_lines:
        n = _norm_link(line)
        if n and n not in seen_norm:
            seen_norm.add(n)
            lines.append(line)
    if len(lines) != len(raw_lines):
        print(f"Дедупликация: {len(raw_lines)} → {len(lines)} уникальных прокси")

    merged_dedup = "\n".join(lines) + ("\n" if lines else "")
    with open(wl_path, "w", encoding="utf-8") as f:
        f.write(merged_dedup)
    wl_top_path = os.path.join(configs_dir, "white-list_available(top100)")
    top100 = lines[:100]
    with open(wl_top_path, "w", encoding="utf-8") as f:
        f.write("\n".join(top100) + ("\n" if top100 else ""))
    print(f"Итог: white-list_available = {len(lines)} конфигов (Xray + Hysteria), top100 записан.")
    sys.exit(0)


if __name__ == "__main__":
    main()
