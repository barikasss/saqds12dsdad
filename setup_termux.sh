#!/data/data/com.termux/files/usr/bin/bash
# setup_termux.sh — White IP Hunter setup for Termux on Android (Samsung Note 9)
# Requires: Termux >= 0.118, Python >= 3.11
set -e

REPO_URL="https://github.com/YOUR_USER/white-ip-hunter.git"   # замени на реальный URL
INSTALL_DIR="$HOME/white-ip-hunter"

echo "[1/6] Обновление пакетов..."
pkg update -y && pkg upgrade -y

echo "[2/6] Установка зависимостей системы..."
pkg install -y python git openssh
# ping/traceroute — нужен для ICMP-сканирования (требует root)
pkg install -y iputils 2>/dev/null || pkg install -y inetutils 2>/dev/null || true
echo "  ping: $(which ping 2>/dev/null || echo 'не найден — используй --no-icmp')"

echo "[3/6] Клонирование / обновление репозитория..."
if [ -d "$INSTALL_DIR/.git" ]; then
    echo "  Репозиторий уже есть, обновляем..."
    git -C "$INSTALL_DIR" pull --ff-only
else
    git clone "$REPO_URL" "$INSTALL_DIR"
fi
cd "$INSTALL_DIR"

echo "[4/6] Python-зависимости..."
pip install --upgrade pip
pip install -r requirements.txt

echo "[5/6] Инициализация конфига..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo ""
    echo "  ⚠️  Заполни .env перед запуском!"
    echo "     Переменные для редактирования:"
    echo "       SELECTEL_ACCOUNT_ID  — 6-значный номер аккаунта"
    echo "       SELECTEL_USERNAME    — логин сервисного пользователя"
    echo "       SELECTEL_PASSWORD    — пароль сервисного пользователя"
    echo "       SELECTEL_PROJECT_ID  — UUID проекта"
    echo "       WLCHECKER_API_KEY    — ключ WLChecker"
    echo "       TG_BOT_TOKEN         — токен Telegram-бота"
    echo "       TG_CHAT_ID           — твой числовой Telegram ID"
    echo ""
    echo "  Скопируй .env с PC через SCP:"
    echo "    scp .env <user>@<android-ip>:$INSTALL_DIR/"
    echo "  Или через Termux:API:"
    echo "    nano .env   (вставь вручную)"
fi
if [ ! -f config.yaml ]; then
    cp config.example.yaml config.yaml
    echo "  Создан config.yaml — проверь priority_subnets и region"
fi

echo "[6/6] Проверка импортов..."
python -c "from src.orchestrator import Orchestrator; print('✅ Готово к запуску')"

echo ""
echo "════════════════════════════════════════"
echo "  Команды запуска:"
echo ""
echo "  # Dry-run (без создания IP):"
echo "  python -m src.orchestrator --dry-run --phase 1 --no-icmp"
echo ""
echo "  # Phase 1 — приоритетные подсети:"
echo "  python -m src.orchestrator --phase 1 --no-icmp"
echo ""
echo "  # Ночной прогон (все подсети):"
echo "  nohup python -m src.orchestrator --phase both --no-icmp \\"
echo "      > data/night_run.log 2>&1 &"
echo "  echo \"PID: \$!\""
echo ""
echo "  # Статистика:"
echo "  python -m src.subnet_source --stats"
echo "════════════════════════════════════════"
