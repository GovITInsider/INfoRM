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

### Prerequisites

- Python 3.9+
- systemd (for running as a service)
- Root/sudo access (for initial setup)

### 1. Installation from Source

```bash
git clone https://github.com/YOUR_USERNAME/INfoRM.git
cd INfoRM

python -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

### 2. Configuration

```bash
cp config/config.yaml.example config/config.yaml
cp .env.example .env
```

Edit the following files:
- config/config.yaml - Configure general settings, monitoring, and web options
- .env - Add your secret key (__IMPORTANT__):
```env
SECURITY__SECRET_KEY=your-very-long-random-secret-here
```

### 3. Create Admin User

```bash
python -m inform.cli.main create-admin
```

### 4. Running INfoRM

__Development__ (with auto-reload)
```bash
uvicorn web.main:app --reload
```

__Production__ (recommended):
```bash
sudo systemctl start inform-web.service
sudo systemctl start inform-monitor.service
```

Enable services to start on boot:
```bash
sudo systemctl enable inform-web.service
sudo systemctl enable inform-monitor.service
```

Check status:
```bash
sudo systemctl status inform-web.service
sudo systemctl status inform-monitor.service
```

### Access the Web Interface

- __NOC View:__ http://your-server:8000/noc
- __Devices Page:__ http://your-server:8000/devices
- __Management GUI:__ http://your-server:8000/manage

### Configuration

Main configuration is split between two files:
- config/config.yaml - Non-sensitive settings (refresh intervals, monitoring thresholds, etc.)
- .env - Sensitive values (especially the secret key)

Key settings:
- SECURITY__SECRET_KEY (in .env) — Required for authentication
- web.noc_auto_refresh_seconds — Auto-refresh interval for the NOC page
- monitoring.countbeforealarm — Number of failed pings before marking a device as Down

### Usage

#### Management GUI (Recommended)

Log in at /manage to manage buildings and devices.

#### CLI Tools

```bash
python -m inform.cli.main --help
```

Common commands:
- create-admin
- add-device
- list-devices
- edit-devices <ip>
- search-devices <term>

#### Project Structure

```
INfoRM/
├── inform/                 # Core application logic
│   ├── cli/                # Command-line interface
│   ├── core/               # Database, models, monitoring, auth
│   └── version.py
├── web/                    # FastAPI web application
│   ├── templates/          # Jinja2 templates
│   ├── static/             # CSS, JS, images
│   └── main.py
├── config/                 # Configuration files
├── data/                   # SQLite database (created at runtime)
├── logs/                   # Application logs
└── systemd/                # systemd service files
```

#### License
This project is licensed under the MIT License (LICENSE).

#### Version
Current version: 1.0.0For detailed usage instructions, refer to the in-app Help page after logging into the management interface.

#### Contributing
Contributions are welcome! Please open an issue first to discuss major changes.
