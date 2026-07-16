#!/bin/bash
set -e

echo "=== INfoRM Installation Script ==="

# Variables
INSTALL_DIR="/opt/inform-ng"
SERVICE_USER="inform"

echo "Creating system user: $SERVICE_USER"
sudo useradd --system --no-create-home --shell /usr/sbin/nologin $SERVICE_USER || true

echo "Creating installation directory..."
sudo mkdir -p $INSTALL_DIR
sudo chown $USER:$USER $INSTALL_DIR

echo "Copying application files..."
cp -r . $INSTALL_DIR/

echo "Setting up virtual environment..."
cd $INSTALL_DIR
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "Creating data and logs directories..."
mkdir -p data logs
python -c "from inform.core.database import init_db; init_db()"

echo "Setting correct ownership..."
sudo chown -R $SERVICE_USER:$SERVICE_USER $INSTALL_DIR

echo "Installing systemd services..."
sudo cp systemd/inform-monitor.service /etc/systemd/system/
sudo cp systemd/inform-web.service /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable --now inform-monitor.service
sudo systemctl enable --now inform-web.service

echo ""
echo "=== Installation Complete ==="
echo "Web interface should be available at: http://$(hostname -I | awk '{print $1}'):8000"
echo ""
echo "Useful commands:"
echo "  sudo systemctl status inform-web"
echo "  sudo systemctl status inform-monitor"
echo "  journalctl -u inform-web -f"
