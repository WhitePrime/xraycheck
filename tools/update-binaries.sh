#!/usr/bin/env bash
# Устанавливает или обновляет Xray и Hysteria в tools/.
# Если бинарников нет - ставит (сначала пробует latest по redirect, при ошибке - фиксированная версия).
# Если есть - пробует обновить до latest; при 403/rate limit оставляет как есть.

set -e
REPO_ROOT="${GITHUB_WORKSPACE:-.}"
TOOLS="$REPO_ROOT/tools"
mkdir -p "$TOOLS"

# Фиксированные версии на случай, если redirect (releases/latest) вернёт 403
XRAY_FALLBACK="${XRAY_FALLBACK:-v1.8.4}"
HYSTERIA_FALLBACK="${HYSTERIA_FALLBACK:-v2.4.2}"

get_latest_tag() {
  local url="$1"
  local redirect
  redirect=$(curl -sI "$url" 2>/dev/null | grep -i "^location:" | awk '{print $2}' | tr -d '\r\n')
  if [[ -n "$redirect" ]]; then
    basename "$redirect"
  fi
}

# --- Xray ---
xray_updated=0
xray_tag=""
xray_redirect="https://github.com/XTLS/Xray-core/releases/latest"
if xray_tag=$(get_latest_tag "$xray_redirect") && [[ -n "$xray_tag" ]]; then
  xray_tag="v${xray_tag#v}"
  echo "Xray latest tag: $xray_tag"
  if curl -sSL -f -o "$TOOLS/xray.zip" "https://github.com/XTLS/Xray-core/releases/download/${xray_tag}/Xray-linux-64.zip"; then
    unzip -j -o "$TOOLS/xray.zip" xray -d "$TOOLS"
    rm -f "$TOOLS/xray.zip"
    chmod +x "$TOOLS/xray"
    xray_updated=1
    echo "Xray updated: $TOOLS/xray"
  fi
fi
if [[ $xray_updated -eq 0 ]]; then
  if [[ ! -f "$TOOLS/xray" ]]; then
    echo "Using fallback Xray $XRAY_FALLBACK..."
    curl -sSL -o "$TOOLS/xray.zip" "https://github.com/XTLS/Xray-core/releases/download/${XRAY_FALLBACK}/Xray-linux-64.zip"
    unzip -j -o "$TOOLS/xray.zip" xray -d "$TOOLS"
    rm -f "$TOOLS/xray.zip"
    chmod +x "$TOOLS/xray"
    xray_updated=1
  else
    echo "Keeping existing Xray (could not fetch latest)."
  fi
fi

# --- Hysteria (tag в URL: app/vX.Y.Z) ---
hyst_updated=0
hyst_redirect="https://github.com/apernet/hysteria/releases/latest"
# Редирект даёт .../tag/app%2Fv2.4.2 -> тег app/v2.4.2
hyst_tag_raw=$(curl -sI "$hyst_redirect" 2>/dev/null | grep -i "^location:" | tail -1 | awk '{print $2}' | tr -d '\r\n')
if [[ -n "$hyst_tag_raw" ]]; then
  hyst_tag=$(basename "$hyst_tag_raw" | sed 's/%2F/\//g')
  echo "Hysteria latest tag: $hyst_tag"
  if curl -sSL -f -o "$TOOLS/hysteria" "https://github.com/apernet/hysteria/releases/download/${hyst_tag}/hysteria-linux-amd64"; then
    chmod +x "$TOOLS/hysteria"
    hyst_updated=1
    echo "Hysteria updated: $TOOLS/hysteria"
  fi
fi
if [[ $hyst_updated -eq 0 ]]; then
  if [[ ! -f "$TOOLS/hysteria" ]]; then
    echo "Using fallback Hysteria $HYSTERIA_FALLBACK..."
    curl -sSL -o "$TOOLS/hysteria" "https://github.com/apernet/hysteria/releases/download/app/${HYSTERIA_FALLBACK}/hysteria-linux-amd64"
    chmod +x "$TOOLS/hysteria"
    hyst_updated=1
  else
    echo "Keeping existing Hysteria (could not fetch latest)."
  fi
fi
