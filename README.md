<div align="center">

# XRayCheck

> **Технический анализ конфигураций VLESS, VMess, Trojan, Shadowsocks, Hysteria и MTProto с возможностью эмуляции сетевых ограничений**

---

> ⚠️ **Данные предоставляются исключительно в информационных целях.**
>
> ⚠️ **Любое использование конфигураций возможно только с согласия их владельцев**
> 
> ⚠️ **Настоящий инструмент выполняет только техническую валидацию доступности сетевых endpoint**
> 
> ⚠️ **Инструмент не создаёт VPN-соединений и не маршрутизирует пользовательский трафик через третьи лица**


---

| [**Исходный код**](https://github.com/WhitePrime/xraycheck/tree/main) | | [**Локальный запуск**](#локальный-запуск) | 

| [**Техническая информация**](#техническая-информация) |



| [**DMCA Takedown**](#-dmca-takedown) | 


> [**Telegram**](https://t.me/XRayCheck)

</div>

---

<div align="center">

## 📊 Статистика репозитория

| Показатель                             | Значение |
| ------------------------------------------------ | ---------------- |
| Просмотры (14Д)                        | 3 856|
| Уникальные посетители (14Д) | 992|
| Клоны (14Д)                                | 11 270|
| Уникальные клоны (14Д)           | 2 609|
| Звёзды                                     | 34|
| Форки                                       | 5|

</div>

---
---

## 📮 DMCA Takedown

Если вы являетесь владельцем сервера, чьи конфигурации были обнаружены в данном репозитории, и вы хотите их удалить:

<div align="center">

| Способ | Действие |
|--------|----------|
| **GitHub Issue** | Создайте [Issue](https://github.com/WhitePrime/xraycheck/issues/new) с тегом `[Takedown]` в заголовке |
| **Telegram** | Напишите в [Telegram-бот для обратной связи](https://t.me/XRayCheckSupportBot) |

</div>

### Что нужно указать в запросе

Обязательно:
- [ ] Домен или IP-адрес сервера для удаления
- [ ] Доказательство владения (одно из):
  - Запись WHOIS домена
  - Счёт от хостинг-провайдера (реквизиты и персональные данные можно замазать)
  - DNS TXT-запись: `v=removal-request-xraycheck`
  - Письмо с корпоративного email на домене сервера

Опционально:
- Причина удаления (утечка, устаревшие данные, ошибочное добавление)
- Предпочтительный способ связи для подтверждения

### Сроки обработки

- **Первичный ответ**: в течение 48 часов
- **Удаление из репозитория**: в течение 72 часов после подтверждения владения
- **Обновление GitHub Pages**: до 24 часов после удаления из репозитория

---
---

<div align="center">


# Техническая информация

</div>

---

Поддерживаемые протоколы: **VLESS**, **VMess**, **Trojan**, **Shadowsocks**


## Требования

- **Python 3.8+**
- **Xray-core** - при первом запуске, если xray не найден в PATH и не задан`XRAY_PATH`, скрипт **автоматически скачает** нужную сборку с [GitHub Releases](https://github.com/XTLS/Xray-core/releases) в папку`xray_dist` рядом со скриптом. Ручная установка не обязательна.

## Установка

```bash
pip install -r requirements.txt
```

## Режимы работы

- **single** - Валидация ключей из одной ссылки (аргумент командной строки или`DEFAULT_LIST_URL`).
- **merge** - Объединение ключей из нескольких ссылок и валидация одной группы. Ссылки задаются в файле`links.txt` (по одной URL на строку). Имя файла задаётся в`.env` переменной`LINKS_FILE`.

## Режимы проверки ключей

- **Обычный** (`STRONG_STYLE_TEST=false`) - несколько тестовых URL (HTTP и/или HTTPS), повторные запросы, проверки стабильности. Настраивается через`TEST_URLS`,`TEST_URLS_HTTPS`,`MIN_SUCCESSFUL_URLS`,`REQUIRE_HTTPS`,`STABILITY_CHECKS` и др.
- **Строгий** (`STRONG_STYLE_TEST=true`) - один тестовый URL`https://www.gstatic.com/generate_204`, один или два запроса подряд, без повторов. Ключ считается рабочим только при ответе 204, пустом теле и времени ответа не более`STRONG_MAX_RESPONSE_TIME` секунд. Результаты ближе к поведению мобильных клиентов.

Полный список переменных - в `.env.example`.

---

---

<div align="center">

# Локальный запуск

</div>

## Запуск

Список по умолчанию (режим single):

```bash
python vless_checker.py
```

Свой URL списка (режим single):

```bash
python vless_checker.py "https://example.com/my-vless-list.txt"
```

Режим merge: положите ссылки в `links.txt`, в `.env` задайте `MODE=merge`:

```bash
# В links.txt по одной URL на строку, например:
# https://example.com/list1.txt
# https://example.com/list2.txt
python vless_checker.py
```

## Запуск через скрипты (рекомендуется)

Для удобства запуска доступны интерактивные скрипты, которые предлагают выбор между обычной проверкой и проверкой в Docker, а также автоматически проверяют и устанавливают зависимости.

### Windows: bat-скрипт (самый простой способ)

Для Windows доступен нативный bat-скрипт `run_check.bat` с интерактивным меню:

1. Дважды кликните на`run_check.bat` в проводнике Windows, или
2. Запустите из командной строки или PowerShell:
   ```cmd
   run_check.bat
   ```

**Особенности:**

- **Интерактивное меню** с выбором стрелками ↑↓ и подтверждением Enter
- **Центрированное отображение** меню в консоли
- **Цветная подсветка** выбранного пункта
- Автоматическая проверка и установка зависимостей Python

**Использование:**

- Используйте стрелки ↑↓ для навигации по меню
- Нажмите Enter для выбора пункта
- Нажмите Escape для выхода

С передачей аргументов (например, URL списка):

```cmd
run_check.bat "https://example.com/my-list.txt"
```

> **Примечание:** Скрипт использует встроенный PowerShell для интерактивного меню. Убедитесь, что PowerShell доступен в вашей системе (обычно установлен по умолчанию в Windows 10/11).

### Linux/macOS: bash скрипт

Для Linux и macOS используйте bash скрипт `run_check.sh` с интерактивным меню:

```bash
chmod +x run_check.sh
./run_check.sh
```

**Особенности:**

- **Интерактивное меню** с выбором стрелками ↑↓ и подтверждением Enter
- **Центрированное отображение** меню в терминале
- **Цветная подсветка** выбранного пункта
- Автоматическая проверка и установка зависимостей Python

**Использование:**

- Используйте стрелки ↑↓ для навигации по меню
- Нажмите Enter для выбора пункта
- Нажмите Escape или 'q' для выхода

С передачей аргументов (например, URL списка):

```bash
./run_check.sh "https://example.com/my-list.txt"
```

## Настройки (файл `.env`)

Параметры задаются в **`.env`** в каталоге проекта (или через переменные окружения). Полный шаблон со значениями по умолчанию - **`.env.example`**.

<details>
<summary><strong>Основные и вывод</strong></summary>

| Переменная | Описание |
|------------|----------|
| `MODE` | Режим: `single` (одна ссылка) или `merge` (объединение списков из файла) |
| `DEFAULT_LIST_URL` | URL списка по умолчанию при `MODE=single` |
| `LINKS_FILE` | Файл со ссылками при `MODE=merge` (по одной URL на строку) |
| `OUTPUT_FILE` | Имя файла для рабочих ключей без расширения (напр. `available`) |
| `OUTPUT_DIR` | Директория для результатов (`configs`) |
| `OUTPUT_ADD_DATE` | Добавлять дату и источник к имени файла (`true`/`false`) |

</details>

<details>
<summary><strong>Тестовые URL и валидация</strong></summary>

| Переменная | Описание |
|------------|----------|
| `TEST_URL`, `TEST_URLS` | URL для проверки (HTTP), при нескольких - через запятую |
| `TEST_URLS_HTTPS` | HTTPS URL (напр. `https://www.gstatic.com/generate_204`) |
| `REQUIRE_HTTPS` | Требовать успешный HTTPS для признания ключа рабочим |
| `STRONG_STYLE_TEST` | Строгий режим как в мобильных клиентах (`true`/`false`) |
| `STRONG_STYLE_TIMEOUT` | Таймаут одного запроса в строгом режиме, сек. |
| `STRONG_MAX_RESPONSE_TIME` | В строгом режиме макс. время ответа, сек. |
| `STRONG_DOUBLE_CHECK` | В строгом режиме два запроса подряд, оба должны пройти |
| `STRONG_ATTEMPTS` | Число подряд успешных запросов к generate_204 (3 = строже) |

</details>

<details>
<summary><strong>Запросы и таймауты</strong></summary>

| Переменная | Описание |
|------------|----------|
| `REQUESTS_PER_URL` | Число запросов к каждому URL |
| `MIN_SUCCESSFUL_REQUESTS` | Минимум успешных запросов к одному URL |
| `MIN_SUCCESSFUL_URLS` | Минимум успешных URL для признания ключа рабочим |
| `REQUEST_DELAY` | Задержка между запросами к одному URL, сек. |
| `CONNECT_TIMEOUT` | Таймаут HTTP-запроса через прокси, сек. |
| `CONNECT_TIMEOUT_SLOW` | Таймаут для медленных соединений, сек. |
| `USE_ADAPTIVE_TIMEOUT` | Адаптивные таймауты (`true`/`false`) |
| `MAX_RETRIES` | Макс. повторов при ошибке соединения |
| `RETRY_DELAY_BASE`, `RETRY_DELAY_MULTIPLIER` | Задержка между повторами (экспоненциальная) |

</details>

<details>
<summary><strong>Ответы и фильтры</strong></summary>

| Переменная | Описание |
|------------|----------|
| `MAX_RESPONSE_TIME` | Макс. допустимое время ответа, сек. (0 = не ограничивать) |
| `MIN_RESPONSE_SIZE` | Минимальный размер ответа в байтах (0 = не проверять) |
| `MAX_LATENCY_MS` | Макс. задержка в мс; ключи выше не попадают в результат |
| `VERIFY_HTTPS_SSL` | Проверять SSL при HTTPS через прокси (`false` типично для SOCKS) |

</details>

<details>
<summary><strong>Геолокация и стабильность</strong></summary>

| Переменная | Описание |
|------------|----------|
| `CHECK_GEOLOCATION` | Проверять геолокацию прокси |
| `GEOLOCATION_SERVICE` | URL сервиса геолокации |
| `ALLOWED_COUNTRIES` | Разрешённые страны (пусто = все) |
| `STABILITY_CHECKS` | Число проверок стабильности |
| `STABILITY_CHECK_DELAY` | Задержка между валидациями стабильности, сек. |
| `STRICT_MODE`, `STRICT_MODE_REQUIRE_ALL` | Строгий режим: требовать все проверки |

</details>

<details>
<summary><strong>Производительность и xray</strong></summary>

| Переменная | Описание |
|------------|----------|
| `MAX_WORKERS` | Число потоков (параллельных проверок) |
| `BASE_PORT` | Начальный порт для SOCKS (диапазон BASE_PORT … BASE_PORT+MAX_WORKERS-1) |
| `XRAY_STARTUP_WAIT` | Ожидание старта xray, сек. |
| `XRAY_STARTUP_POLL_INTERVAL` | Интервал опроса процесса xray, сек. |
| `XRAY_PATH` | Путь к xray (пусто = поиск в PATH и автоустановка в `xray_dist`) |
| `XRAY_DIR_NAME` | Папка для скачанного xray |

</details>

<details>
<summary><strong>Отладка, логи, метрики, кэш</strong></summary>

| Переменная | Описание |
|------------|----------|
| `DEBUG_FIRST_FAIL` | Вывод отладки при первой неудаче |
| `LOG_LEVEL` | Уровень логирования (DEBUG, INFO, WARNING, ERROR) |
| `LOG_FILE`, `LOG_MAX_SIZE`, `LOG_BACKUP_COUNT` | Файл логов и ротация |
| `LOG_RESPONSE_TIME` | Писать время ответа в результаты |
| `LOG_METRICS` | Логировать метрики производительности |
| `METRICS_FILE` | Файл для метрик |
| `MIN_AVG_RESPONSE_TIME` | Мин. среднее время ответа, сек. (0 = не ограничивать) |
| `TEST_POST_REQUESTS` | Проверять POST-запросы |
| `ENABLE_CACHE` | Кэширование результатов проверки |
| `CACHE_TTL`, `CACHE_FILE` | Время жизни кэша и файл кэша |

</details>

<details>
<summary><strong>Speedtest (speedtest_checker.py)</strong></summary>

| Переменная | Описание |
|------------|----------|
| `SPEED_TEST_ENABLED` | Включить speedtest (`true`/`false`) |
| `SPEED_TEST_TIMEOUT` | Макс. секунд на конфиг для фазы задержки |
| `SPEED_TEST_MODE` | Режим: `latency`, `quick` (250KB), `full` (1MB) |
| `SPEED_TEST_METRIC` | Метрика при latency: `latency`, `throughput`, `hybrid` |
| `SPEED_TEST_OUTPUT` | Куда писать: `separate_file` (_st, _st(top100)) |
| `SPEED_TEST_REQUESTS` | Число запросов для фазы задержки |
| `SPEED_TEST_URL` | URL для проверки задержки (generate_204) |
| `SPEED_TEST_WORKERS` | Число потоков для speedtest |
| `SPEED_TEST_DOWNLOAD_TIMEOUT` | Макс. секунд на загрузку тестового файла |
| `SPEED_TEST_DOWNLOAD_URL_SMALL`, `SPEED_TEST_DOWNLOAD_URL_MEDIUM` | URL для загрузки (quick/full) |
| `MIN_SPEED_THRESHOLD_MBPS` | Отсев по скорости, Mbps (0 = не фильтровать) |

</details>

<details>
<summary><strong>Экспорт</strong></summary>

| Переменная | Описание |
|------------|----------|
| `EXPORT_FORMAT` | Формат экспорта: txt, json, csv, html, all |
| `EXPORT_DIR` | Директория для экспорта |

</details>

