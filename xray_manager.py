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

import config
from config import (
    XRAY_DIR_NAME,
    XRAY_RELEASES_API,
    XRAY_STARTUP_POLL_INTERVAL,
    XRAY_STARTUP_WAIT,
)

console = Console()


def build_xray_config(parsed: dict, socks_port: int) -> dict:
    """Собирает конфиг xray: inbound SOCKS, outbound VLESS (Reality)."""
    user = {"id": parsed["uuid"], "encryption": "none"}
    if parsed.get("flow"):
        user["flow"] = parsed["flow"]

    stream = {
        "network": parsed["network"],
        "security": parsed["security"],
    }
    if parsed["security"] == "reality":
        stream["realitySettings"] = {
            "fingerprint": parsed.get("fingerprint") or "chrome",
            "serverName": parsed.get("serverName") or "",
            "publicKey": parsed.get("publicKey") or "",
            "shortId": parsed.get("shortId") or "",
        }
    if parsed["network"] == "grpc":
        stream["grpcSettings"] = {"serviceName": ""}
    if parsed["network"] == "xhttp":
        stream["xhttpSettings"] = {"mode": parsed.get("mode") or "auto"}

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
            {
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": parsed["address"],
                            "port": parsed["port"],
                            "users": [user],
                        }
                    ]
                },
                "streamSettings": stream,
                "tag": "proxy",
            },
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


def _download_xray_to(dir_path: str) -> str | None:
    """
    Скачивает Xray-core с GitHub в dir_path. Возвращает путь к исполняемому файлу или None.
    """
    asset_name = _get_xray_platform_asset_name()
    if not asset_name:
        console.print(f"[yellow]Платформа не поддерживается для автоустановки:[/yellow] {platform.system()} / {platform.machine()}")
        return None
    try:
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
        zip_path = os.path.join(dir_path, "xray.zip")
        with requests.get(download_url, stream=True, timeout=60) as resp:
            resp.raise_for_status()
            with open(zip_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=65536):
                    f.write(chunk)
        exe_name = "xray.exe" if sys.platform == "win32" else "xray"
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
                        os.remove(zip_path)
                    except OSError:
                        pass
                    return os.path.abspath(extracted)
        # Fallback: распаковать всё и найти xray
        with zipfile.ZipFile(zip_path, "r") as z:
            z.extractall(dir_path)
        try:
            os.remove(zip_path)
        except OSError:
            pass
        for root, _dirs, files in os.walk(dir_path):
            for f in files:
                if f.lower() == exe_name or (exe_name == "xray" and f == "xray"):
                    return os.path.abspath(os.path.join(root, f))
        console.print("[red]В архиве не найден исполняемый файл xray.[/red]")
        return None
    except requests.RequestException as e:
        console.print(f"[red]Ошибка загрузки Xray-core:[/red] {e}")
        return None
    except zipfile.BadZipFile as e:
        console.print(f"[red]Ошибка архива:[/red] {e}")
        return None
    except Exception as e:
        console.print(f"[red]Ошибка установки Xray:[/red] {e}")
        return None


def ensure_xray() -> bool:
    """
    Убеждается, что xray доступен: проверяет PATH, затем локальную папку xray_dist,
    при необходимости скачивает Xray-core с GitHub. Возвращает True, если xray готов к использованию.
    """
    import config
    if os.environ.get("XRAY_PATH"):
        return check_xray_available()
    if check_xray_available():
        return True
    script_dir = os.path.dirname(os.path.abspath(__file__))
    xray_dir = os.path.join(script_dir, XRAY_DIR_NAME)
    exe_name = "xray.exe" if sys.platform == "win32" else "xray"
    local_path = os.path.join(xray_dir, exe_name)
    if os.path.isfile(local_path):
        # Используем глобальную переменную из config
        config.XRAY_CMD = local_path
        if check_xray_available():
            console.print(f"[green]✓[/green] Используется локальный Xray: {local_path}\n")
            return True
    os.makedirs(xray_dir, exist_ok=True)
    path = _download_xray_to(xray_dir)
    if path:
        config.XRAY_CMD = path
        if check_xray_available():
            console.print(f"[green]✓[/green] Xray-core установлен: {path}\n")
            return True
    return False
