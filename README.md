<div align="center">

# XRaycheck - проверка VPN-ключей (end-to-end)

> Автоматически обновляемая коллекция публичных VPN-конфигов:
> (**VLESS**, **VMess**, **Trojan**, **Shadowsocks**)

[**сайт**](https://whiteprime.github.io/xraycheck/)

[**файлы в configs**](https://github.com/WhitePrime/xraycheck/tree/main/configs)


</div>

****

<div align="center">
   
## 📊 Статистика репозитория



| Показатель | Значение |
|------------|----------|
| Просмотры (14Д) | 0 |
| Уникальные посетители (14Д) | 0 |
| Клоны (14Д) | 0 |
| Уникальные клоны (14Д) | 0 |
| Звёзды | 0 |
| Форки | 0 |

</div>


****

<details>

<summary>Техническая информация</summary>


****

<div align="center">
   
**[Исходный код](https://github.com/WhitePrime/xraycheck/tree/main)**
   
</div>


****



Поддерживаемые протоколы: **VLESS**, **VMess**, **Trojan**, **Shadowsocks**

Скрипт загружает список прокси-ключей по URL и выполняет **end-to-end** проверку каждого ключа:

1. Запускает локальный прокси (xray) с этим ключом (SOCKS на 127.0.0.1).
2. Делает HTTP(S)-запрос к тестовому URL **через прокси**.
3. По ответу (статус, время, при необходимости несколько URL и повторные запросы) ключ считается рабочим или мёртвым.

Рабочие ключи сохраняются в директории `configs/`: `available.txt` (без даты в имени). При запуске через Docker - в `configs/white-list_available.txt`.

## Требования

- **Python 3.8+**
- **Xray-core** - при первом запуске, если xray не найден в PATH и не задан `XRAY_PATH`, скрипт **автоматически скачает** нужную сборку с [GitHub Releases](https://github.com/XTLS/Xray-core/releases) в папку `xray_dist` рядом со скриптом. Ручная установка не обязательна.

## Установка

```bash
pip install -r requirements.txt
```

## Режимы работы

- **single** - проверка ключей из одной ссылки (аргумент командной строки или `DEFAULT_LIST_URL`).
- **merge** - объединение ключей из нескольких ссылок и проверка одной группы. Ссылки задаются в файле `links.txt` (по одной URL на строку). Имя файла задаётся в `.env` переменной `LINKS_FILE`.

## Режимы проверки ключей

- **Обычный** (`STRONG_STYLE_TEST=false`) - несколько тестовых URL (HTTP и/или HTTPS), повторные запросы, проверки стабильности. Настраивается через `TEST_URLS`, `TEST_URLS_HTTPS`, `MIN_SUCCESSFUL_URLS`, `REQUIRE_HTTPS`, `STABILITY_CHECKS` и др.
- **Строгий** (`STRONG_STYLE_TEST=true`) - один тестовый URL `https://www.gstatic.com/generate_204`, один или два запроса подряд, без повторов. Ключ считается рабочим только при ответе 204, пустом теле и времени ответа не более `STRONG_MAX_RESPONSE_TIME` секунд. Результаты ближе к поведению мобильных клиентов.

Полный список переменных - в `.env.example`.

</details>

<details>

<summary>Локальный запуск (Python & Docker)</summary>

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

1. Дважды кликните на `run_check.bat` в проводнике Windows, или
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

Параметры задаются в **`.env`** в каталоге проекта (или через переменные окружения). Шаблон со всеми опциями - **`.env.example`**.

| Переменная | Описание |
|------------|----------|
| `MODE` | Режим: `single` или `merge` |
| `LINKS_FILE` | Файл со ссылками при `MODE=merge` (по одной URL на строку) |
| `DEFAULT_LIST_URL` | URL списка по умолчанию (при `MODE=single`) |
| `OUTPUT_FILE` | Базовое имя файла для рабочих ключей (`available.txt`) |
| `OUTPUT_DIR` | Директория для результатов (`configs`) |
| `TEST_URL`, `TEST_URLS` | URL для проверки (HTTP); при нескольких - через запятую |
| `TEST_URLS_HTTPS` | HTTPS URL (например `https://www.gstatic.com/generate_204`) |
| `REQUIRE_HTTPS` | Требовать успешный HTTPS для признания ключа рабочим |
| `STRONG_STYLE_TEST` | Строгий режим: один URL, 1-2 запроса, лимит по времени (`true`/`false`) |
| `STRONG_STYLE_TIMEOUT` | Таймаут одного запроса в строгом режиме, сек. |
| `STRONG_MAX_RESPONSE_TIME` | В строгом режиме макс. время ответа, сек. (медленнее - мёртвый) |
| `STRONG_DOUBLE_CHECK` | В строгом режиме делать два запроса, оба должны успешно пройти |
| `CONNECT_TIMEOUT` | Таймаут запроса через прокси, сек. |
| `MAX_RESPONSE_TIME` | Макс. допустимое время ответа, сек. (0 = не ограничивать) |
| `MAX_WORKERS` | Число потоков (параллельных проверок) |
| `BASE_PORT` | Начальный порт для SOCKS (порты BASE_PORT ... BASE_PORT+MAX_WORKERS-1) |
| `XRAY_STARTUP_WAIT` | Ожидание старта xray, сек. |
| `XRAY_STARTUP_POLL_INTERVAL` | Интервал опроса процесса xray, сек. |
| `XRAY_PATH` | Путь к xray (пусто = поиск в PATH и автоустановка) |
| `XRAY_DIR_NAME` | Папка для скачанного xray |
| `VERIFY_HTTPS_SSL` | Проверять SSL при HTTPS-запросах через прокси (`false` типично для SOCKS) |
| `DEBUG_FIRST_FAIL` | Вывод отладки при первой неудаче (`true`/`false`) |

Остальные параметры (повторы, стабильность, геолокация, строгий режим проверки всех URL и т.д.) описаны в `.env.example`.

## Docker: эмуляция ограничения по CIDR whitelist

В контейнере исходящий доступ ограничен только подсетями из [CIDR whitelist](https://github.com/hxehex/russia-mobile-internet-whitelist).

- **Сборка и запуск:** `docker compose up --build` (или `docker compose run --rm vless-checker`)
- **Результат:** файл с рабочими ключами создаётся в `configs/` на хосте (volume `.:/app`)
- **Свой URL списка:** `docker compose run --rm vless-checker "https://example.com/keys.txt"`
- **Режим merge:** положите `links.txt` в каталог проекта (volume `.:/app`), задайте в `.env` `MODE=merge` и запустите `docker compose run --rm vless-checker`
- Требуется `cap_add: NET_ADMIN` для iptables внутри контейнера

</details>

<details>

<summary>Github Action</summary>

## GitHub Actions: ежедневное обновление available.txt

В репозитории настроен workflow **Daily VLESS check** (`.github/workflows/daily-check.yml`):

- **Расписание:** три раза в день в 7:10 | 14:10 | 19:10 MSK (cron).
- **Действия:** запуск `vless_checker.py` в режиме `merge` (списки из `links.txt`), результат пишется в `configs/available.txt`; при изменении файла коммит и push в текущую ветку.
- **Ручной запуск:** вкладка Actions → «Daily VLESS check» → Run workflow.

**Чтобы не публиковать `links.txt` в репозитории:** файл `links.txt` уже попадает под маску `*.txt` в `.gitignore`. В CI он создаётся из секрета. Добавьте в репозитории **Settings → Secrets and variables → Actions** секрет с именем **`LINKS_FILE_CONTENT`** и значением - содержимое вашего `links.txt` (по одной URL на строку). Workflow перед запуском проверки запишет этот секрет во временный `links.txt`. Если секрет не задан, шаг «Create links.txt from secret» завершится с ошибкой. Если `links.txt` уже был закоммичен ранее, удалите его из истории и добавьте секрет: `git rm --cached links.txt` и коммит.

</details>
