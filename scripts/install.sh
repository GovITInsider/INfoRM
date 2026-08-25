#!/bin/bash
set -euo pipefail

echo "=== INfoRM Installation Script ==="
echo ""

INSTALL_DIR="/opt/inform-ng"
SERVICE_USER="inform"
REQUIRED_PY_MAJOR=3
REQUIRED_PY_MINOR_MIN=12

if [ "${EUID}" -ne 0 ]; then
    echo "This script must be run with sudo."
    echo "Example: sudo bash scripts/install.sh"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [ ! -f "${PROJECT_ROOT}/inform/core/database.py" ] || [ ! -f "${PROJECT_ROOT}/requirements.txt" ]; then
    echo "Could not locate the INfoRM project root from ${SCRIPT_DIR}."
    echo "Run: sudo bash scripts/install.sh"
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive

echo "Installing system packages..."
apt-get update -qq
apt-get install -y --no-install-recommends \
    ca-certificates \
    iputils-ping \
    openssl \
    python3 \
    python3-pip \
    python3-venv \
    rsync

# Prefer the 3.12 packages when the distro provides them (Ubuntu 24.04).
if apt-cache show python3.12 >/dev/null 2>&1; then
    apt-get install -y --no-install-recommends python3.12 python3.12-venv || true
fi

PYTHON_BIN=""
if command -v python3.12 >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3.12)"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3)"
else
    echo "Python 3 is not installed."
    exit 1
fi

PY_VERSION="$("${PYTHON_BIN}" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
PY_MAJOR="${PY_VERSION%%.*}"
PY_MINOR="${PY_VERSION#*.}"

if [ "${PY_MAJOR}" -lt "${REQUIRED_PY_MAJOR}" ] || { [ "${PY_MAJOR}" -eq "${REQUIRED_PY_MAJOR}" ] && [ "${PY_MINOR}" -lt "${REQUIRED_PY_MINOR_MIN}" ]; }; then
    echo "INfoRM requires Python ${REQUIRED_PY_MAJOR}.${REQUIRED_PY_MINOR_MIN} or newer."
    echo "Found: Python ${PY_VERSION} (${PYTHON_BIN})"
    echo ""
    echo "On Ubuntu 24.04 LTS:"
    echo "  sudo apt-get install python3.12 python3.12-venv"
    echo "On Ubuntu 26.04 LTS, the default python3 (3.14) is supported."
    exit 1
fi

echo "Using ${PYTHON_BIN} (Python ${PY_VERSION})"

if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
    echo "Creating system user: ${SERVICE_USER}"
    useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
else
    echo "System user ${SERVICE_USER} already exists"
fi

echo "Creating installation directory..."
mkdir -p "${INSTALL_DIR}"

systemctl stop inform-web.service 2>/dev/null || true
systemctl stop inform-monitor.service 2>/dev/null || true

echo "Copying application files from ${PROJECT_ROOT}..."
rsync -a \
    --exclude '.git/' \
    --exclude 'venv/' \
    --exclude 'data/' \
    --exclude 'logs/' \
    --exclude '__pycache__/' \
    --exclude '*.pyc' \
    --exclude '.env' \
    --exclude 'config/config.yaml' \
    "${PROJECT_ROOT}/" "${INSTALL_DIR}/"

mkdir -p "${INSTALL_DIR}/data" "${INSTALL_DIR}/logs"
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${INSTALL_DIR}"

echo "Setting up Python virtual environment..."
rm -rf "${INSTALL_DIR}/venv"
sudo -u "${SERVICE_USER}" "${PYTHON_BIN}" -m venv "${INSTALL_DIR}/venv"
sudo -u "${SERVICE_USER}" "${INSTALL_DIR}/venv/bin/pip" install --upgrade pip
sudo -u "${SERVICE_USER}" "${INSTALL_DIR}/venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt"

echo "Setting up configuration files..."
if [ ! -f "${INSTALL_DIR}/config/config.yaml" ]; then
    cp "${INSTALL_DIR}/config/config.yaml.example" "${INSTALL_DIR}/config/config.yaml"
    echo "  → Created config/config.yaml (edit this file as needed)"
fi

if [ ! -f "${INSTALL_DIR}/.env" ]; then
    if [ ! -f "${INSTALL_DIR}/.env.example" ]; then
        echo "Missing ${INSTALL_DIR}/.env.example"
        exit 1
    fi
    SECRET="$(openssl rand -hex 32)"
    sed "s/your-very-long-random-secret-key-here/${SECRET}/" \
        "${INSTALL_DIR}/.env.example" > "${INSTALL_DIR}/.env"
    echo "  → Created .env with a generated SECURITY__SECRET_KEY"
fi

chown -R "${SERVICE_USER}:${SERVICE_USER}" "${INSTALL_DIR}/config" "${INSTALL_DIR}/.env"

echo "Initializing database..."
sudo -u "${SERVICE_USER}" bash -c "cd \"${INSTALL_DIR}\" && ./venv/bin/python -c 'from inform.core.database import init_db; init_db()'"

echo "Installing systemd services..."
if [ ! -f "${PROJECT_ROOT}/systemd/inform-web.service" ] || [ ! -f "${PROJECT_ROOT}/systemd/inform-monitor.service" ]; then
    echo "Missing systemd unit files in ${PROJECT_ROOT}/systemd/"
    exit 1
fi
cp "${PROJECT_ROOT}/systemd/inform-web.service" /etc/systemd/system/
cp "${PROJECT_ROOT}/systemd/inform-monitor.service" /etc/systemd/system/

systemctl daemon-reload
systemctl enable --now inform-web.service
systemctl enable --now inform-monitor.service

HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
if [ -z "${HOST_IP}" ]; then
    HOST_IP="127.0.0.1"
fi

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Next steps:"
echo "1. Review configuration (optional):"
echo "   sudo nano ${INSTALL_DIR}/config/config.yaml"
echo "   sudo nano ${INSTALL_DIR}/.env"
echo ""
echo "2. Create an admin user:"
echo "   cd ${INSTALL_DIR}"
echo "   sudo -u ${SERVICE_USER} ./venv/bin/python -m inform.cli.main create-admin"
echo ""
echo "3. Access the web interface:"
echo "   http://${HOST_IP}:8000/manage"
echo ""
echo "Useful commands:"
echo "  sudo systemctl status inform-web"
echo "  sudo systemctl status inform-monitor"
echo "  journalctl -u inform-web -f"
echo "  journalctl -u inform-monitor -f"
