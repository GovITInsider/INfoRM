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
- systemd (for service management)
- Root/sudo access for initial installation

### Installation

1. Extract the release archive:

    ```bash
    tar -xzvf inform-ng-v1.0.tar.gz
    cd inform-ng
    ```

2. Run the installation script:

    ```bash
    sudo bash scripts/install.sh
    ```

3. Create the admin user:

    ```bash
    python -m inform.cli.main create-admin
    ```

4. Start the services:

    ```bash
    systemctl start inform-web.service
    systemctl start inform-monitor.service
    ```

### Access the Web Interface

- **Landing Page**: `http://your-server:8000`
- **NOC View**: `http://your-server:8000/noc`
- **Devices Page**: `http://your-server:8000/devices`
- **Management GUI**: `http://your-server:8000/manage` (login required)

### Configuration

Main configuration file: `config/config.yaml`

Key settings include:

- `security.secret_key` — Change this on first setup
- `web.noc_auto_refresh_seconds` — Auto-refresh interval for the NOC page
- `monitoring.countbeforealarm` — Number of failed pings before marking a device as Down

### Usage

#### Management GUI (Recommended)

Log in at `/manage` to:

- Manage Buildings (add/edit/delete)
- Manage Devices (add/edit/delete with building dropdown)

#### CLI (Advanced / Scripting)

```bash
python -m inform.cli.main --help
```
Common commands:create-admin
add-device
list-devices
edit-device <ip>
search-devices <term>



#### Project Structure

```
inform-ng/
├── inform/                 # Core application code
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
└── systemd/                # Service unit files
```

#### License
This project is licensed under the MIT License.

#### Version
Current version: 1.0.0

For detailed usage instructions, please refer to the in-app Help page after logging into the web interface.
