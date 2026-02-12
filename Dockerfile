# Проверка VLESS в контейнере с доступом только к whitelist + хостам прокси
FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    unzip \
    curl \
    ca-certificates \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Скачать Xray-core (Linux amd64) с GitHub
RUN set -eux; \
    API='https://api.github.com/repos/XTLS/Xray-core/releases/latest'; \
    URL=$(curl -sL "$API" | jq -r '.assets[] | select(.name == "Xray-linux-64.zip") | .browser_download_url'); \
    curl -sL "$URL" -o /tmp/xray.zip; \
    unzip -o /tmp/xray.zip -d /tmp/xe; \
    find /tmp/xe -type f -name xray -exec mv {} /usr/local/bin/ \;; \
    chmod +x /usr/local/bin/xray; \
    rm -rf /tmp/xray.zip /tmp/xe

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY vless_checker.py docker_entrypoint.py ./

# Путь к xray в контейнере
ENV XRAY_PATH=/usr/local/bin/xray

# Точка входа: настройка iptables по whitelist + хостам прокси, затем запуск скрипта
ENTRYPOINT ["python", "docker_entrypoint.py"]
CMD []
