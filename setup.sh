#!/usr/bin/env bash
#
# Recon Framework — Quick Setup Script
# Works on Linux, macOS, and Windows (Git Bash / WSL)
#
set -euo pipefail

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}"
echo "  ____  _____ ____  _   _ ______   _____ _____ _   _ ______ _____  "
echo " |  _ \| ____/ ___|| \ | |  _ \ \ / /_ _|  ___| \ | |  ____|  ___| "
echo " | |_) |  _|| |    |  \| | | | \ V / | || |_  |  \| | |__  | |_    "
echo " |  _ <| |__| |___ | |\  | |_|  | |  | ||  _| | |\  |  __| |  _|   "
echo " |_| \_\_____\____||_| \_|____/  |_| |___|_|   |_| \_|_|    |_|     "
echo -e "${NC}"
echo -e "${CYAN}  Zero-cost open-source reconnaissance framework${NC}"
echo ""

# ── Check Python ───────────────────────────────────
check_python() {
    if command -v python3 &>/dev/null; then
        PYTHON=python3
    elif command -v python &>/dev/null; then
        PYTHON=python
    else
        echo -e "${RED}[!] Python 3.10+ is required but not found.${NC}"
        echo "    Install from: https://www.python.org/downloads/"
        exit 1
    fi
    VERSION=$($PYTHON -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    echo -e "${GREEN}[✓] Python ${VERSION} found${NC}"
}

# ── Check Docker ───────────────────────────────────
check_docker() {
    if command -v docker &>/dev/null && command -v docker-compose &>/dev/null; then
        echo -e "${GREEN}[✓] Docker found${NC}"
        HAS_DOCKER=1
    elif command -v docker &>/dev/null && docker compose version &>/dev/null; then
        echo -e "${GREEN}[✓] Docker (with compose plugin) found${NC}"
        HAS_DOCKER=1
    else
        echo -e "${YELLOW}[!] Docker not found (optional, for containerized setup)${NC}"
        HAS_DOCKER=0
    fi
}

# ── Install ────────────────────────────────────────
install_local() {
    echo ""
    echo -e "${CYAN}[*] Installing Recon Framework...${NC}"
    $PYTHON -m pip install --upgrade pip -q
    $PYTHON -m pip install -r requirements.txt -q
    $PYTHON -m pip install flask gunicorn -q
    $PYTHON -m pip install -e . -q
    echo -e "${GREEN}[✓] Installation complete${NC}"
}

# ── Menu ───────────────────────────────────────────
echo ""
echo -e "${CYAN}Choose setup method:${NC}"
echo ""
echo "  1) Local install  (pip, runs on host)"
echo "  2) Docker         (containerized, recommended for production)"
echo "  3) Both"
echo ""
read -p "Enter choice [1-3]: " CHOICE

check_python
check_docker

case ${CHOICE:-1} in
    1)
        install_local
        echo ""
        echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}  Setup complete! Usage:${NC}"
        echo ""
        echo -e "  ${CYAN}CLI:${NC}   python -m recon_framework.cli --target example.com --mode hybrid"
        echo -e "  ${CYAN}Web:${NC}   python -m flask --app recon_framework.web.app:create_app run"
        echo -e "  ${CYAN}Help:${NC}  python -m recon_framework.cli --help"
        echo -e "  ${CYAN}Mods:${NC}  python -m recon_framework.cli --list-modules"
        echo ""
        echo -e "  Web UI: ${CYAN}http://localhost:5000${NC}"
        echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
        ;;
    2)
        if [ "$HAS_DOCKER" -eq 0 ]; then
            echo -e "${RED}[!] Docker is required for option 2. Install Docker first.${NC}"
            exit 1
        fi
        echo ""
        echo -e "${CYAN}[*] Building Docker image...${NC}"
        docker-compose up -d --build
        echo ""
        echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}  Docker container running!${NC}"
        echo ""
        echo -e "  Web UI: ${CYAN}http://localhost:5000${NC}"
        echo -e "  Logs:   ${CYAN}docker-compose logs -f${NC}"
        echo -e "  Stop:   ${CYAN}docker-compose down${NC}"
        echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
        ;;
    3)
        install_local
        if [ "$HAS_DOCKER" -eq 1 ]; then
            echo ""
            echo -e "${CYAN}[*] Building Docker image...${NC}"
            docker-compose up -d --build
        fi
        echo ""
        echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}  Full setup complete!${NC}"
        echo ""
        echo -e "  ${CYAN}CLI:${NC}   python -m recon_framework.cli --target example.com"
        echo -e "  ${CYAN}Web:${NC}   http://localhost:5000"
        echo -e "  ${CYAN}Docker:${NC} docker-compose up -d"
        echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
        ;;
    *)
        echo -e "${RED}Invalid choice${NC}"
        exit 1
        ;;
esac
