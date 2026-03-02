# Проверка VLESS в контейнере с доступом только к whitelist + хостам прокси
FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    unzip \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Xray и Hysteria — те же версии и способ, что в daily-check (tools/setup-binaries.sh): прямые URL, без API
COPY tools/setup-binaries.sh /work/tools/
RUN set -eux; \
    REPO_ROOT=/work GITHUB_WORKSPACE=/work bash /work/tools/setup-binaries.sh; \
    mv /work/tools/xray /work/tools/hysteria /usr/local/bin/; \
    chmod +x /usr/local/bin/xray /usr/local/bin/hysteria; \
    rm -rf /work

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY vless_checker.py speedtest_checker.py hysteria_checker.py speedtest_hysteria.py ./
COPY lib/ ./lib/

# Пути к бинарникам в контейнере (избегаем скачивания в рантайме)
ENV XRAY_PATH=/usr/local/bin/xray
ENV HYSTERIA_PATH=/usr/local/bin/hysteria

# Точка входа: настройка iptables по whitelist + хостам прокси, затем запуск vless_checker.py
ENTRYPOINT ["python", "-m", "lib.docker_entrypoint"]
CMD []
