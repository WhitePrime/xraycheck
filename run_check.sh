#!/bin/bash

# Скрипт для запуска проверки прокси-ключей
# Предлагает выбор между обычной проверкой и проверкой в Docker с белыми списками

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Функция для вывода сообщений
info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Функция проверки и установки зависимостей Python
check_and_install_requirements() {
    info "Проверка зависимостей Python..."
    
    # Проверяем наличие pip
    if ! command -v pip3 &> /dev/null && ! command -v pip &> /dev/null; then
        error "pip не найден. Установите pip для продолжения."
        exit 1
    fi
    
    # Определяем команду pip
    PIP_CMD="pip3"
    if ! command -v pip3 &> /dev/null; then
        PIP_CMD="pip"
    fi
    
    # Проверяем наличие requirements.txt
    if [ ! -f "requirements.txt" ]; then
        error "Файл requirements.txt не найден!"
        exit 1
    fi
    
    # Проверяем установленные пакеты используя pip show
    MISSING_PACKAGES=()
    
    while IFS= read -r line; do
        # Пропускаем пустые строки и комментарии
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        
        # Извлекаем имя пакета (до >= или ==)
        PACKAGE_NAME=$(echo "$line" | sed -E 's/[[:space:]]*(>=|==|<=|<|>).*//' | xargs)
        
        if [ -n "$PACKAGE_NAME" ]; then
            # Проверяем установлен ли пакет через pip show
            if ! $PIP_CMD show "$PACKAGE_NAME" &> /dev/null; then
                MISSING_PACKAGES+=("$line")
            fi
        fi
    done < requirements.txt
    
    # Устанавливаем недостающие пакеты
    if [ ${#MISSING_PACKAGES[@]} -gt 0 ]; then
        warning "Обнаружены отсутствующие зависимости:"
        for pkg in "${MISSING_PACKAGES[@]}"; do
            echo "  - $pkg"
        done
        
        info "Установка зависимостей..."
        if $PIP_CMD install -r requirements.txt; then
            success "Зависимости успешно установлены!"
        else
            error "Ошибка при установке зависимостей!"
            exit 1
        fi
    else
        success "Все зависимости уже установлены."
    fi
}

# Функция проверки наличия Docker
check_docker() {
    if ! command -v docker &> /dev/null; then
        error "Docker не найден. Установите Docker для использования этого режима."
        exit 1
    fi
    
    if ! command -v docker compose &> /dev/null && ! command -v docker-compose &> /dev/null; then
        error "Docker Compose не найден. Установите Docker Compose для использования этого режима."
        exit 1
    fi
}

# Функция обычной проверки
run_normal_check() {
    info "Запуск обычной проверки..."
    
    # Проверяем наличие Python
    if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
        error "Python не найден. Установите Python 3.8+ для продолжения."
        exit 1
    fi
    
    # Определяем команду python
    PYTHON_CMD="python3"
    if ! command -v python3 &> /dev/null; then
        PYTHON_CMD="python"
    fi
    
    # Проверяем наличие vless_checker.py
    if [ ! -f "vless_checker.py" ]; then
        error "Файл vless_checker.py не найден!"
        exit 1
    fi
    
    # Проверяем и устанавливаем зависимости
    check_and_install_requirements
    
    # Запускаем проверку
    success "Запуск vless_checker.py..."
    $PYTHON_CMD vless_checker.py "$@"
}

# Функция проверки в Docker с белыми списками
run_docker_check() {
    info "Запуск проверки в Docker с белыми списками..."
    
    check_docker
    
    # Проверяем наличие docker-compose.yml
    if [ ! -f "docker-compose.yml" ]; then
        error "Файл docker-compose.yml не найден!"
        exit 1
    fi
    
    # Определяем команду docker compose
    DOCKER_COMPOSE_CMD="docker compose"
    if ! command -v docker compose &> /dev/null; then
        DOCKER_COMPOSE_CMD="docker-compose"
    fi
    
    # Запускаем Docker контейнер
    success "Запуск Docker контейнера..."
    $DOCKER_COMPOSE_CMD run --rm vless-checker "$@"
}

# Функция для чтения одной клавиши
read_key() {
    local key
    IFS= read -rsn1 key 2>/dev/null || return 1
    if [[ $key == $'\x1b' ]]; then
        read -rsn2 key
    fi
    echo "$key"
}

# Функция для центрирования текста
center_text() {
    local text="$1"
    local width
    width=$(tput cols 2>/dev/null || echo 80)
    # Убираем ANSI коды для подсчета длины
    local clean_text=$(echo "$text" | sed 's/\x1b\[[0-9;]*m//g')
    local text_length=${#clean_text}
    local padding=$(( (width - text_length) / 2 ))
    printf "%*s%s\n" $padding "" "$text"
}

# Интерактивное меню с выбором стрелками
interactive_menu() {
    local options=("Обычная проверка" "Проверка при белых списках" "Выход")
    local descriptions=(
        "Запуск vless_checker.py локально"
        "Запуск в Docker с ограничением по CIDR whitelist"
        ""
    )
    local selected=0
    local key
    local width
    width=$(tput cols 2>/dev/null || echo 80)
    
    while true; do
        # Очищаем экран и показываем меню
        clear
        echo ""
        center_text "=========================================="
        center_text "  Проверка прокси-ключей (xraycheck)"
        center_text "=========================================="
        echo ""
        center_text "Выберите режим проверки (используйте стрелки ↑↓ и Enter):"
        echo ""
        
        for i in "${!options[@]}"; do
            if [ $i -eq $selected ]; then
                local option_text="▶ ${options[$i]}"
                local opt_length=${#option_text}
                local opt_padding=$(( (width - opt_length) / 2 ))
                printf "%*s${BOLD}${CYAN}%s${NC}\n" $opt_padding "" "$option_text"
                if [ -n "${descriptions[$i]}" ]; then
                    local desc_text="  ${descriptions[$i]}"
                    local desc_length=${#desc_text}
                    local desc_padding=$(( (width - desc_length) / 2 ))
                    printf "%*s${CYAN}%s${NC}\n" $desc_padding "" "$desc_text"
                fi
            else
                local option_text="  ${options[$i]}"
                local opt_length=${#option_text}
                local opt_padding=$(( (width - opt_length) / 2 ))
                printf "%*s%s\n" $opt_padding "" "$option_text"
                if [ -n "${descriptions[$i]}" ]; then
                    local desc_text="    ${descriptions[$i]}"
                    local desc_length=${#desc_text}
                    local desc_padding=$(( (width - desc_length) / 2 ))
                    printf "%*s%s\n" $desc_padding "" "$desc_text"
                fi
            fi
            echo ""
        done
        
        # Читаем клавишу
        key=$(read_key)
        
        case "$key" in
            '[A'|'A')  # Стрелка вверх
                if [ $selected -gt 0 ]; then
                    ((selected--))
                fi
                ;;
            '[B'|'B')  # Стрелка вниз
                if [ $selected -lt $((${#options[@]} - 1)) ]; then
                    ((selected++))
                fi
                ;;
            '')  # Enter
                return $selected
                ;;
            'q'|'Q'|$'\x1b')  # q или Escape
                return 2
                ;;
        esac
    done
}

# Основной цикл
main() {
    # Переходим в директорию скрипта
    cd "$(dirname "$0")"
    
    # Показываем интерактивное меню
    interactive_menu
    local choice=$?
    
    case $choice in
        0)
            echo ""
            run_normal_check "$@"
            ;;
        1)
            echo ""
            run_docker_check "$@"
            ;;
        2)
            info "Выход..."
            exit 0
            ;;
        *)
            error "Неверный выбор."
            exit 1
            ;;
    esac
}

# Запуск главной функции
main "$@"
