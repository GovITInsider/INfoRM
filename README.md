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

- Python 3.12+ (3.12 on Ubuntu 24.04 LTS; 3.14 on Ubuntu 26.04 LTS)
- FastAPI + Uvicorn
- SQLAlchemy + SQLite
- Jinja2 + Bootstrap 5
- fastapi-login (authentication)
- passlib + bcrypt (password hashing)

## Getting Started

### Requirements

- Ubuntu 24.04 LTS or Ubuntu 26.04 LTS
- Python 3.12 or newer (the installer prefers `python3.12` when present, otherwise `python3`)
- Root / sudo access
- Outbound HTTPS for `apt` and PyPI during install

### Installation

The recommended way to install INfoRM is the included installation script. It can be run from any directory:

```bash
git clone https://github.com/GovITInsider/INfoRM.git
cd INfoRM
sudo bash scripts/install.sh
```

The script:

- Checks for Python 3.12+ and installs OS packages (`python3-venv`, `iputils-ping`, `rsync`)
- Creates a dedicated system user (`inform`)
- Copies the application to `/opt/inform-ng`
- Creates a Python 3.12 virtual environment and installs dependencies
- Creates `data/` and `logs/` directories
- Copies example configuration files if they do not already exist
- Generates a random `SECURITY__SECRET_KEY` in `.env` on first install
- Initializes the SQLite database (creates all tables)
- Installs and starts the `inform-web` and `inform-monitor` systemd services

Re-running the script updates application files and recreates the virtual environment. Existing `config/config.yaml`, `.env`, and `data/` contents are preserved.

### Configure INfoRM

After installation, review the configuration files:

```bash
sudo nano /opt/inform-ng/config/config.yaml
sudo nano /opt/inform-ng/.env
```

A secret key is generated automatically. Replace it only if you need to set your own value for `SECURITY__SECRET_KEY`.

### Create Admin User

```bash
cd /opt/inform-ng
sudo -u inform ./venv/bin/python -m inform.cli.main create-admin
```

### Access the Web Interface

- **NOC View:** http://your-server:8000/noc
- **Devices Page:** http://your-server:8000/devices
- **Management GUI:** http://your-server:8000/manage

Log in to `/manage` with the admin credentials created above.

## Configuration

INfoRM uses two configuration files:

- `config/config.yaml` — General settings (monitoring intervals, auto-refresh, etc.)
- `.env` — Sensitive values (`SECURITY__SECRET_KEY` used for authentication)

After running the installation script, both files are created from example templates. Review them before using the system in production.

## Usage

### Management GUI (Recommended)

The web interface at `/manage` is the easiest way to manage buildings and devices. Add buildings first; devices must be assigned to an existing building.

### CLI Tools

```bash
cd /opt/inform-ng
sudo -u inform ./venv/bin/python -m inform.cli.main --help
```

Common commands:

- `create-admin`
- `add-device`
- `list-devices`
- `edit-device <ip>`
- `search-devices <term>`

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

## Troubleshooting

**`INfoRM requires Python 3.12 or newer`**  
The installer found Python older than 3.12 (commonly 3.10 on Ubuntu 22.04). Use Ubuntu 24.04+ or install Python 3.12+.

**`python3 -m venv` / `ensurepip` fails**  
Install the venv package for 3.12: `sudo apt-get install python3.12-venv python3-venv`.

**`no such table: users` when creating an admin**  
The database was created without models registered. Re-run the installer (1.1.2 or later) or:

```bash
cd /opt/inform-ng
sudo -u inform ./venv/bin/python -c 'from inform.core.database import init_db; init_db()'
```

**`Form data requires "python-multipart"`**  
The virtualenv was built from an old `requirements.txt`. Re-run the installer, or `sudo -u inform /opt/inform-ng/venv/bin/pip install -r /opt/inform-ng/requirements.txt` and restart `inform-web`.

**`AttributeError: module 'bcrypt' has no attribute '__about__'` (or passlib/bcrypt errors)**  
passlib 1.7.4 needs bcrypt 4.0.x. Use the pinned `requirements.txt` (`bcrypt>=4.0.1,<4.1.0`) and recreate the venv by re-running the installer.

**`Failed to start inform-web.service` / missing unit files**  
Confirm `systemd/inform-web.service` and `systemd/inform-monitor.service` exist in the cloned repo, then re-run the installer. Check `journalctl -u inform-web -e`.

**Services start but `/manage` is unreachable**  
Confirm `inform-web` is listening on port 8000 (`ss -lntp | grep 8000`) and that the host firewall allows TCP/8000.

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
Current version: 1.1.2
