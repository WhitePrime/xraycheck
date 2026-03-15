@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion

REM Скрипт для запуска проверки прокси-ключей
REM Предлагает выбор между обычной проверкой и проверкой в Docker с белыми списками

REM Переходим в директорию скрипта
cd /d "%~dp0"

REM Используем PowerShell для интерактивного меню
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
"$Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size(120, 3000); ^
$options = @('Обычная проверка', 'Проверка при белых списках', 'Выход'); ^
$descriptions = @('Запуск vless_checker.py локально', 'Запуск в Docker с ограничением по CIDR whitelist', ''); ^
$selected = 0; ^
function Center-Text { ^
    param([string]$text, [int]$width); ^
    $padding = [Math]::Floor(($width - $text.Length) / 2); ^
    return (' ' * $padding) + $text; ^
}; ^
function Show-Menu { ^
    Clear-Host; ^
    $width = $Host.UI.RawUI.BufferSize.Width; ^
    Write-Host ''; ^
    Write-Host (Center-Text '==========================================' $width) -ForegroundColor Cyan; ^
    Write-Host (Center-Text '  Проверка прокси-ключей (xraycheck)' $width) -ForegroundColor Cyan; ^
    Write-Host (Center-Text '==========================================' $width) -ForegroundColor Cyan; ^
    Write-Host ''; ^
    Write-Host (Center-Text 'Выберите режим проверки (используйте стрелки ↑↓ и Enter):' $width) -ForegroundColor Yellow; ^
    Write-Host ''; ^
    for ($i = 0; $i -lt $options.Length; $i++) { ^
        if ($i -eq $selected) { ^
            $optText = '▶ ' + $options[$i]; ^
            Write-Host (Center-Text $optText $width) -ForegroundColor Cyan -NoNewline; ^
            Write-Host ''; ^
            if ($descriptions[$i]) { ^
                $descText = '  ' + $descriptions[$i]; ^
                Write-Host (Center-Text $descText $width) -ForegroundColor Cyan; ^
            } ^
        } else { ^
            $optText = '  ' + $options[$i]; ^
            Write-Host (Center-Text $optText $width); ^
            if ($descriptions[$i]) { ^
                $descText = '    ' + $descriptions[$i]; ^
                Write-Host (Center-Text $descText $width); ^
            } ^
        } ^
        Write-Host ''; ^
    } ^
}; ^
do { ^
    Show-Menu; ^
    $key = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown'); ^
    switch ($key.VirtualKeyCode) { ^
        38 { if ($selected -gt 0) { $selected-- } } ^
        40 { if ($selected -lt ($options.Length - 1)) { $selected++ } } ^
        13 { break } ^
        27 { $selected = 2; break } ^
    } ^
} while ($key.VirtualKeyCode -ne 13 -and $key.VirtualKeyCode -ne 27); ^
exit $selected"

set choice=%ERRORLEVEL%

if "%choice%"=="0" goto :run_normal
if "%choice%"=="1" goto :run_docker
if "%choice%"=="2" goto :exit_script

echo [ERROR] Неверный выбор.
pause
exit /b 1

:run_normal
echo.
echo [INFO] Запуск обычной проверки...

REM Проверяем наличие Python
where python >nul 2>&1
if errorlevel 1 (
    where python3 >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] Python не найден. Установите Python 3.8+ для продолжения.
        pause
        exit /b 1
    ) else (
        set "PYTHON_CMD=python3"
    )
) else (
    set "PYTHON_CMD=python"
)

REM Проверяем наличие vless_checker.py
if not exist "vless_checker.py" (
    echo [ERROR] Файл vless_checker.py не найден!
    pause
    exit /b 1
)

REM Проверяем и устанавливаем зависимости
call :check_and_install_requirements
if errorlevel 1 (
    pause
    exit /b 1
)

REM Запускаем проверку
echo [SUCCESS] Запуск vless_checker.py...
!PYTHON_CMD! vless_checker.py %*
goto :end

:run_docker
echo.
echo [INFO] Запуск проверки в Docker с белыми списками...

REM Проверяем наличие Docker
where docker >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker не найден. Установите Docker для использования этого режима.
    pause
    exit /b 1
)

REM Проверяем docker compose
docker compose version >nul 2>&1
if errorlevel 1 (
    docker-compose version >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] Docker Compose не найден. Установите Docker Compose для использования этого режима.
        pause
        exit /b 1
    ) else (
        set "DOCKER_COMPOSE_CMD=docker-compose"
    )
) else (
    set "DOCKER_COMPOSE_CMD=docker compose"
)

REM Проверяем наличие docker-compose.yml
if not exist "docker-compose.yml" (
    echo [ERROR] Файл docker-compose.yml не найден!
    pause
    exit /b 1
)

REM Пересобираем Docker образ (чтобы использовать новую структуру с lib/)
echo [INFO] Пересборка Docker образа...
!DOCKER_COMPOSE_CMD! build --no-cache
if errorlevel 1 (
    echo [ERROR] Ошибка при сборке Docker образа!
    pause
    exit /b 1
)

REM Запускаем Docker контейнер
echo [SUCCESS] Запуск Docker контейнера...
!DOCKER_COMPOSE_CMD! run --rm vless-checker %*
goto :end

:check_and_install_requirements
echo [INFO] Проверка зависимостей Python...

REM Проверяем наличие pip
where pip >nul 2>&1
if errorlevel 1 (
    where pip3 >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] pip не найден. Установите pip для продолжения.
        exit /b 1
    ) else (
        set "PIP_CMD=pip3"
    )
) else (
    set "PIP_CMD=pip"
)

REM Проверяем наличие requirements.txt
if not exist "requirements.txt" (
    echo [ERROR] Файл requirements.txt не найден!
    exit /b 1
)

REM Упрощенная проверка: пытаемся импортировать основные модули
REM Если не получается - устанавливаем все зависимости
set "NEED_INSTALL=0"

REM Проверяем основные пакеты через Python
python -c "import requests" >nul 2>&1
if errorlevel 1 (
    set "NEED_INSTALL=1"
) else (
    python -c "import dotenv" >nul 2>&1
    if errorlevel 1 (
        set "NEED_INSTALL=1"
    ) else (
        python -c "import rich" >nul 2>&1
        if errorlevel 1 (
            set "NEED_INSTALL=1"
        )
    )
)

REM Устанавливаем зависимости если нужно
if !NEED_INSTALL! equ 1 (
    echo [WARNING] Обнаружены отсутствующие зависимости.
    echo [INFO] Установка зависимостей из requirements.txt...
    !PIP_CMD! install -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] Ошибка при установке зависимостей!
        exit /b 1
    ) else (
        echo [SUCCESS] Зависимости успешно установлены!
    )
) else (
    echo [SUCCESS] Все зависимости уже установлены.
)
exit /b 0

:exit_script
echo [INFO] Выход...
goto :end

:end
endlocal
exit /b 0
