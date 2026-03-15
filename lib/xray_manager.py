#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Модуль управления xray: конфигурация, запуск, остановка, загрузка.
"""

import json
import os
import platform
import signal
import subprocess
import sys
import tempfile
import time
import zipfile

import requests
from rich.console import Console

from . import config
from .config import (
    XRAY_DIR_NAME,
    XRAY_RELEASES_API,
    XRAY_STARTUP_POLL_INTERVAL,
    XRAY_STARTUP_WAIT,
)

console = Console()


def build_xray_config(parsed: dict, socks_port: int) -> dict:
    """
    Собирает конфиг xray: inbound SOCKS, outbound для различных протоколов.
    Поддерживает: VLESS, VMess, Trojan, Shadowsocks.
    """
    protocol = parsed.get("protocol", "vless")
    address = parsed.get("address", "")
    port = parsed.get("port", 443)
    
    # Базовые stream settings
    network = parsed.get("network", "tcp")
    security = parsed.get("security", "none")
    
    # Для VMess security может быть в поле "tls"
    if protocol == "vmess" and parsed.get("tls"):
        security = parsed.get("tls", "none")
    
    stream = {
        "network": network,
        "security": security,
    }
    
    # Настройки для разных типов безопасности
    if security == "reality":
        stream["realitySettings"] = {
            "fingerprint": parsed.get("fingerprint") or "chrome",
            "serverName": parsed.get("serverName") or "",
            "publicKey": parsed.get("publicKey") or "",
            "shortId": parsed.get("shortId") or "",
        }
    elif security == "tls":
        stream["tlsSettings"] = {
            "serverName": parsed.get("serverName") or "",
            "allowInsecure": False,
        }
    
    # Настройки для разных типов сетей
    network = stream["network"]
    if network == "grpc":
        stream["grpcSettings"] = {
            "serviceName": parsed.get("grpcServiceName") or ""
        }
    elif network == "ws":
        stream["wsSettings"] = {
            "path": parsed.get("wsPath") or "/",
            "headers": {}
        }
        if parsed.get("wsHost"):
            stream["wsSettings"]["headers"]["Host"] = parsed["wsHost"]
    elif network == "xhttp":
        stream["xhttpSettings"] = {"mode": parsed.get("mode") or "auto"}
    elif network == "h2":
        stream["httpSettings"] = {
            "path": parsed.get("wsPath") or "/",
            "host": [parsed.get("wsHost")] if parsed.get("wsHost") else []
        }
    
    # Строим outbound в зависимости от протокола
    outbound = {
        "protocol": protocol,
        "streamSettings": stream,
        "tag": "proxy",
    }
    
    if protocol == "vless":
        user = {"id": parsed.get("uuid", ""), "encryption": "none"}
        if parsed.get("flow"):
            user["flow"] = parsed["flow"]
        outbound["settings"] = {
            "vnext": [
                {
                    "address": address,
                    "port": port,
                    "users": [user],
                }
            ]
        }
    elif protocol == "vmess":
        user = {
            "id": parsed.get("id", ""),
            "alterId": parsed.get("alterId", 0),
            "security": parsed.get("security", "auto"),
        }
        outbound["settings"] = {
            "vnext": [
                {
                    "address": address,
                    "port": port,
                    "users": [user],
                }
            ]
        }
    elif protocol == "trojan":
        outbound["settings"] = {
            "servers": [
                {
                    "address": address,
                    "port": port,
                    "password": parsed.get("password", ""),
                }
            ]
        }
    elif protocol == "shadowsocks":
        outbound["settings"] = {
            "servers": [
                {
                    "address": address,
                    "port": port,
                    "method": parsed.get("method", "aes-256-gcm"),
                    "password": parsed.get("password", ""),
                }
            ]
        }
    else:
        raise ValueError(f"Неподдерживаемый протокол: {protocol}")
    
    return {
        "log": {"loglevel": "error"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"udp": False},
                "tag": "in",
            }
        ],
        "outbounds": [
            outbound,
            {"protocol": "freedom", "tag": "direct"},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "inboundTag": ["in"], "outboundTag": "proxy"}
            ],
        },
    }


def run_xray(config_path: str, stderr_pipe: bool = False):
    """Запуск xray. При stderr_pipe=True stderr возвращается в proc.stderr."""
    kwargs = {
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.PIPE if stderr_pipe else subprocess.DEVNULL,
    }
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    else:
        # Новая сессия - процесс и дочерние можно завершить группой
        kwargs["start_new_session"] = True
    return subprocess.Popen(
        [config.XRAY_CMD, "run", "-config", config_path],
        **kwargs,
    )


def kill_xray_process(proc: subprocess.Popen, drain_stderr: bool = True) -> None:
    """Гарантированно завершает процесс xray и при необходимости дочерние процессы."""
    if proc is None or proc.poll() is not None:
        return
    # Закрываем stderr без блокирующего read() - иначе процесс мог бы не завершиться
    try:
        if drain_stderr and getattr(proc, "stderr", None) and proc.stderr is not None:
            try:
                proc.stderr.close()
            except (OSError, ValueError):
                pass
    except Exception:
        pass
    try:
        proc.terminate()
    except (OSError, ProcessLookupError):
        pass
    try:
        proc.wait(timeout=2)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        if sys.platform != "win32":
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (OSError, ProcessLookupError):
                proc.kill()
        else:
            proc.kill()
    except (OSError, ProcessLookupError):
        pass
    try:
        proc.wait(timeout=1)
    except subprocess.TimeoutExpired:
        pass


def check_xray_available() -> bool:
    """Проверяет, что xray доступен (XRAY_CMD)."""
    try:
        p = subprocess.run(
            [config.XRAY_CMD, "version"],
            capture_output=True,
            timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        return p.returncode == 0
    except FileNotFoundError:
        return False
    except Exception:
        return False


def _get_xray_platform_asset_name() -> str | None:
    """Возвращает имя asset для текущей ОС и архитектуры (без .dgst)."""
    machine = (platform.machine() or "").lower()
    system = (platform.system() or "").lower()
    is_64 = "64" in machine or machine in ("amd64", "x86_64", "aarch64", "arm64")
    is_arm = "arm" in machine or "aarch" in machine
    if system == "windows":
        if is_arm:
            return "Xray-windows-arm64-v8a.zip"
        return "Xray-windows-64.zip" if is_64 else "Xray-windows-32.zip"
    if system == "linux":
        if is_arm:
            return "Xray-linux-arm64-v8a.zip" if "64" in machine or "aarch" in machine else "Xray-linux-arm32-v7a.zip"
        return "Xray-linux-64.zip" if is_64 else "Xray-linux-32.zip"
    if system == "darwin":
        if is_arm:
            return "Xray-macos-arm64-v8a.zip"
        return "Xray-macos-64.zip"
    return None


_XRAY_DOWNLOAD_MAX_ATTEMPTS = 3
_XRAY_DOWNLOAD_RETRY_DELAY = 10


def _download_xray_to(dir_path: str) -> str | None:
    """
    Скачивает Xray-core с GitHub в dir_path. Возвращает путь к исполняемому файлу или None.
    При обрыве соединения выполняет до 3 попыток с паузой 10 с.
    """
    asset_name = _get_xray_platform_asset_name()
    if not asset_name:
        console.print(f"[yellow]Платформа не поддерживается для автоустановки:[/yellow] {platform.system()} / {platform.machine()}")
        return None
    exe_name = "xray.exe" if sys.platform == "win32" else "xray"
    zip_path = os.path.join(dir_path, "xray.zip")
    for attempt in range(1, _XRAY_DOWNLOAD_MAX_ATTEMPTS + 1):
        try:
            if attempt > 1:
                console.print(f"[yellow]Повтор загрузки Xray-core, попытка {attempt}/{_XRAY_DOWNLOAD_MAX_ATTEMPTS}...[/yellow]")
            r = requests.get(XRAY_RELEASES_API, timeout=15)
            r.raise_for_status()
            data = r.json()
            assets = data.get("assets") or []
            download_url = None
            for a in assets:
                name = (a.get("name") or "")
                if name == asset_name and name.endswith(".zip") and not name.endswith(".dgst"):
                    download_url = a.get("browser_download_url")
                    break
            if not download_url:
                console.print(f"[red]Не найден asset для платформы:[/red] {asset_name}")
                return None
            tag = data.get("tag_name", "unknown")
            console.print(f"[cyan]Скачивание Xray-core {tag} ({asset_name})...[/cyan]")
            try:
                os.remove(zip_path)
            except OSError:
                pass
            with requests.get(download_url, stream=True, timeout=90) as resp:
                resp.raise_for_status()
                with open(zip_path, "wb") as f:
                    for chunk in resp.iter_content(chunk_size=65536):
                        f.write(chunk)
            with zipfile.ZipFile(zip_path, "r") as z:
                for info in z.infolist():
                    if info.is_dir():
                        continue
                    base = os.path.basename(info.filename.replace("\\", "/")).lower()
                    if base != exe_name and not (exe_name == "xray" and base == "xray"):
                        continue
                    z.extract(info, dir_path)
                    extracted = os.path.normpath(os.path.join(dir_path, info.filename))
                    if os.path.isfile(extracted):
                        try:
                            os.chmod(extracted, 0o755)
                        except OSError:
                            pass
                        try:
                            os.remove(zip_path)
                        except OSError:
                            pass
                        return os.path.abspath(extracted)
            with zipfile.ZipFile(zip_path, "r") as z:
                z.extractall(dir_path)
            try:
                os.remove(zip_path)
            except OSError:
                pass
            for root, _dirs, files in os.walk(dir_path):
                for f in files:
                    if f.lower() == exe_name or (exe_name == "xray" and f == "xray"):
                        path = os.path.abspath(os.path.join(root, f))
                        try:
                            os.chmod(path, 0o755)
                        except OSError:
                            pass
                        return path
            console.print("[red]В архиве не найден исполняемый файл xray.[/red]")
            return None
        except requests.RequestException as e:
            if os.path.isfile(zip_path):
                try:
                    os.remove(zip_path)
                except OSError:
                    pass
            if attempt < _XRAY_DOWNLOAD_MAX_ATTEMPTS:
                console.print(f"[yellow]Ошибка загрузки (попытка {attempt}): {e}. Повтор через {_XRAY_DOWNLOAD_RETRY_DELAY} с...[/yellow]")
                time.sleep(_XRAY_DOWNLOAD_RETRY_DELAY)
            else:
                console.print(f"[red]Ошибка загрузки Xray-core после {_XRAY_DOWNLOAD_MAX_ATTEMPTS} попыток:[/red] {e}")
                return None
        except zipfile.BadZipFile as e:
            console.print(f"[red]Ошибка архива:[/red] {e}")
            try:
                os.remove(zip_path)
            except OSError:
                pass
            return None
        except Exception as e:
            console.print(f"[red]Ошибка установки Xray:[/red] {e}")
            try:
                os.remove(zip_path)
            except OSError:
                pass
            return None
    return None


def ensure_xray() -> bool:
    """
    Убеждается, что xray доступен: XRAY_PATH, затем tools/xray в репо, PATH, xray_dist,
    при необходимости скачивает Xray-core с GitHub. Возвращает True, если xray готов к использованию.
    """
    if os.environ.get("XRAY_PATH"):
        return check_xray_available()
    if check_xray_available():
        return True
    from pathlib import Path
    script_dir = Path(__file__).resolve().parent
    if script_dir.name == "lib":
        script_dir = script_dir.parent
    exe_name = "xray.exe" if sys.platform == "win32" else "xray"
    tools_xray = script_dir / "tools" / exe_name
    if tools_xray.is_file():
        config.XRAY_CMD = str(tools_xray)
        if check_xray_available():
            console.print(f"[green][OK][/green] Используется Xray из репо: {tools_xray}\n")
            return True
    xray_dir = script_dir / XRAY_DIR_NAME
    local_path = str(xray_dir / exe_name)
    if os.path.isfile(local_path):
        # Используем глобальную переменную из config
        config.XRAY_CMD = local_path
        if check_xray_available():
            console.print(f"[green][OK][/green] Используется локальный Xray: {local_path}\n")
            return True
    os.makedirs(str(xray_dir), exist_ok=True)
    path = _download_xray_to(str(xray_dir))
    if path:
        config.XRAY_CMD = path
        if check_xray_available():
            console.print(f"[green][OK][/green] Xray-core установлен: {path}\n")
            return True
    return False
