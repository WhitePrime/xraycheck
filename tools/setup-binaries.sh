#!/usr/bin/env bash
# Подготовка бинарников Xray и Hysteria для CI: если tools/xray и tools/hysteria
# отсутствуют, скачивает по прямым URL релизов (без вызова GitHub API, чтобы избежать rate limit).
# Версии зафиксированы; при обновлении поменяйте XRAY_VERSION и HYSTERIA_VERSION ниже.

set -e
XRAY_VERSION="${XRAY_VERSION:-v1.8.4}"
# Тег Hysteria: в URL используется префикс app/ (например app/v2.4.2)
HYSTERIA_VERSION="${HYSTERIA_VERSION:-v2.4.2}"
REPO_ROOT="${GITHUB_WORKSPACE:-.}"
TOOLS="$REPO_ROOT/tools"
mkdir -p "$TOOLS"

if [[ ! -f "$TOOLS/xray" ]]; then
  echo "Downloading Xray-core $XRAY_VERSION (direct URL, no API)..."
  curl -sSL -o "$TOOLS/xray.zip" "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-64.zip"
  unzip -j -o "$TOOLS/xray.zip" xray -d "$TOOLS"
  rm -f "$TOOLS/xray.zip"
  chmod +x "$TOOLS/xray"
  echo "Xray installed: $TOOLS/xray"
fi

if [[ ! -f "$TOOLS/hysteria" ]]; then
  echo "Downloading Hysteria $HYSTERIA_VERSION (direct URL, no API)..."
  curl -sSL -o "$TOOLS/hysteria" "https://github.com/apernet/hysteria/releases/download/app/${HYSTERIA_VERSION}/hysteria-linux-amd64"
  chmod +x "$TOOLS/hysteria"
  echo "Hysteria installed: $TOOLS/hysteria"
fi
