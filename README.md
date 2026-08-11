# INfoRM - ICMP Network Reachability Monitor

INfoRM is a modern, lightweight network monitoring tool designed to provide clear visibility into device connectivity across sites and buildings. It features real-time ICMP monitoring, a clean NOC-style dashboard, and a protected web-based management interface.

## Features

- **Real-time ICMP Monitoring** — Continuously checks device reachability
- **Hybrid NOC View** — Color-coded building status with problem buildings shown as cards and healthy buildings in a compact list
- **Status & Response Time Dashboard** — Overview of Up / Pre-Alarm / Down devices plus Min / Avg / Max response times
- **Web Management GUI** — Add, edit, and delete devices and buildings through a protected web interface
- **Building Enforcement** — Devices must be assigned to existing buildings via dropdown
- **Authentication** — Secure login for the management area
- **Alarm History** — Track when devices go down and come back up
- **CLI Tools** — Still available for scripting and advanced use cases
- **Auto-Refresh** — Configurable refresh on the NOC and Devices pages

## Tech Stack

- Python 3.12
- FastAPI + Uvicorn + Gunicorn
- SQLAlchemy + SQLite
- Jinja2 + Bootstrap 5
- fastapi-login (authentication)
- passlib + bcrypt (password hashing)

## Getting Started

### Installation

The recommended way to install INfoRM is by using the included installation script.

#### 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/INfoRM.git
cd INfoRM
```

#### 2. Run the Installation Script 

```bash
sudo bash scripts/install.sh
```
This script automates the following tasks:
- Creates a dedicated system user (`inform`)
- Copies the application to `/opt/inform-ng`
- Sets up a Python virtual environment and installs dependencies
- Creates `data/` and `logs/` directories
- Initializes the database
- Copies example configuration files (`config.yaml` and `.env`)
- Installs and starts the systemd services

#### 3. Configure INfoRM

After installation, edit the configuration files:
```bash
sudo nano /opt/inform-ng/config/config.yaml
sudo nano /opt/inform-ng/.env
```

**Important:** Set a strong, unique value for SECURITY__SECRET_KEY in the `.env` file.


#### 4. Create Admin User

```bash
cd /opt/inform-ng
sudo -u inform ./venv/bin/python -m inform.cli.main create-admin
```

#### 5. Access the Web Interface

Open your browser and go to:
```
http://your-server-ip:8000/manage
```
Log in using the admin credentials you created in the previous step.

## Access the Web Interface

- **NOC View:** http://your-server:8000/noc
- **Devices Page:** http://your-server:8000/devices
- **Management GUI:** http://your-server:8000/manage

## Configuration

INfoRM uses two configuration files:
- config/config.yaml - General settings (monitoring intervals, auto-refresh, etc.)
- .env - Sensitive values (secret key used for authentication)

After running the installation script, both files are created from example templates. You should review and customize them before using the system in production.

## Usage

### Management GUI (Recommended)

The web interface at /manage is the easiest way to manage buildings and devices.

### CLI Tools

You can also manage INfoRM using the command-line interface:

```bash
cd /opt/inform-ng
sudo -u inform ./venv/bin/python -m inform.cli.main --help
```

Common commands:
- create-admin
- add-device
- list-devices
- edit-device <ip>
- search-devices <term>

### Managing the Services
```bash
# Check status
sudo systemctl status inform-web
sudo systemctl status inform-monitor

# Restart services
sudo systemctl restart inform-web
sudo systemctl restart inform-monitor

# View logs
sudo journalctl -u inform-web -f
sudo journalctl -u inform-monitor -f
```

## Project Structure

```
INfoRM/
├── inform/                 # Core application logic
│   ├── cli/                # Command-line tools
│   ├── core/               # Database, models, monitoring, auth
│   └── version.py
├── web/                    # FastAPI web application
│   ├── templates/          # Jinja2 templates
│   ├── static/             # CSS, JS, images
│   └── main.py
├── config/                 # Configuration files
├── data/                   # SQLite database (created at runtime)
├── logs/                   # Application logs
├── scripts/                # Installation and helper scripts
└── systemd/                # systemd service unit files
```

## License
This project is licensed under the MIT License (LICENSE).

## Version
Current version: 1.1.1
