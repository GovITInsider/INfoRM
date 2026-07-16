#!/bin/bash
set -e

echo "=== INfoRM Installation Script ==="
echo ""

INSTALL_DIR="/opt/inform-ng"
SERVICE_USER="inform"

# Make sure script is run with sudo
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run with sudo."
    echo "Example: sudo bash scripts/install.sh"
    exit 1
fi

echo "Creating system user: $SERVICE_USER"
useradd --system --no-create-home --shell /usr/sbin/nologin $SERVICE_USER 2>/dev/null || true

echo "Creating installation directory..."
mkdir -p $INSTALL_DIR
chown $SERVICE_USER:$SERVICE_USER $INSTALL_DIR

echo "Copying application files..."
cp -r . $INSTALL_DIR
chown -R $SERVICE_USER:$SERVICE_USER $INSTALL_DIR

echo "Setting up Python virtual environment..."
sudo -u $SERVICE_USER bash << 'EOF'
cd $INSTALL_DIR
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
EOF

echo "Creating data and logs directories..."
mkdir -p $INSTALL_DIR/data $INSTALL_DIR/logs
chown -R $SERVICE_USER:$SERVICE_USER $INSTALL_DIR/data $INSTALL_DIR/logs

echo "Initializing database..."
sudo -u $SERVICE_USER bash -c "
    cd $INSTALL_DIR && \
    source venv/bin/activate && \
    python -c 'from inform.core.database import init_db; init_db()'
"

echo "Setting up configuration files..."
if [ ! -f "$INSTALL_DIR/config/config.yaml" ]; then
    cp "$INSTALL_DIR/config/config.yaml.example" "$INSTALL_DIR/config/config.yaml"
    echo "  → Created config/config.yaml (edit this file as needed)"
fi

if [ ! -f "$INSTALL_DIR/.env" ]; then
    cp "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"
    echo "  → Created .env file (IMPORTANT: set your SECRET_KEY here)"
fi

chown -R $SERVICE_USER:$SERVICE_USER $INSTALL_DIR/config $INSTALL_DIR/.env

echo "Installing systemd services..."
cp systemd/inform-web.service /etc/systemd/system/
cp systemd/inform-monitor.service /etc/systemd/system/

systemctl daemon-reload
systemctl enable --now inform-web.service
systemctl enable --now inform-monitor.service

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Next steps:"
echo "1. Edit your configuration files:"
echo "   sudo nano $INSTALL_DIR/config/config.yaml"
echo "   sudo nano $INSTALL_DIR/.env"
echo ""
echo "2. Create an admin user:"
echo "   cd $INSTALL_DIR"
echo "   sudo -u inform ./venv/bin/python -m inform.cli.main create-admin"
echo ""
echo "3. Access the web interface:"
echo "   http://$(hostname -I | awk '{print $1}'):8000/manage"
echo ""
echo "Useful commands:"
echo "  sudo systemctl status inform-web"
echo "  sudo systemctl status inform-monitor"
echo "  journalctl -u inform-web -f"
