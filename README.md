# INfoRM - ICMP Network Reachability Monitor

INfoRM is a modern, lightweight network monitoring tool designed to provide clear visibility into device connectivity across sites and buildings. It features real-time ICMP monitoring, a clean NOC-style dashboard, and a protected web-based management interface.

## Features

- **Real-time ICMP Monitoring** — Continuously checks device reachability
- **Hybrid NOC View** — Color-coded building status with problem buildings shown as cards and healthy buildings in a compact list
- **Status & Response Time Dashboard** — Overview of Up / Pre-Alarm / Down devices plus Min / Avg / Max response times
- **Web Management GUI** — Add, edit, and delete devices and buildings through a protected web interface
- **On-demand Discover** — Scan one IPv4 or a CIDR (max `/24`); ping first, then SNMP live hosts; review and bulk-add
- **Credential Profiles** — SNMPv1 / v2c / v3 credentials with a web UI and CLI
- **SNMP identity** — Vendor, model, name, and location from Discover, from **Add Device** when a profile is selected, or from **Refresh SNMP**. Reachability stays ICMP
- **Building Enforcement** — Devices must be assigned to existing buildings via dropdown
- **Authentication** — Secure login for the management area, with 8-hour sessions that renew while you work
- **Alarm History** — Track when devices go down and come back up
- **Inventory export / import** — YAML v2 backup of buildings and devices (vendor, model, profile name; no secrets)
- **CLI Tools** — Still available for scripting and advanced use cases
- **Auto-Refresh** — Configurable refresh on the NOC and Devices pages

## Tech Stack

- Python 3.12+ (3.12 on Ubuntu 24.04 LTS; 3.14 on Ubuntu 26.04 LTS)
- FastAPI + Uvicorn
- SQLAlchemy + SQLite
- Jinja2 + Bootstrap 5
- fastapi-login (authentication)
- passlib + bcrypt (password hashing)
- pysnmp 7.1 (SNMP identity)
- cryptography (SNMPv3 privacy / AES and DES)
- pycryptodomex (AES-256-GCM for credential secrets)

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
- Creates a Python virtual environment (3.12+) and installs dependencies
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

A secret key is generated automatically. `SECURITY__SECRET_KEY` signs admin session cookies **and** encrypts SNMP credential secrets at rest. Replacing it logs everyone out **and** makes existing community / auth / priv values undecryptable until you re-enter them on each profile. There is no re-encrypt CLI; do not rotate the key without re-entering profiles.

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

- `config/config.yaml` — General settings (monitoring intervals, auto-refresh, admin session length, discovery, etc.)
- `.env` — Sensitive values (`SECURITY__SECRET_KEY` used for authentication and credential encryption)

Useful `config.yaml` keys:

- `monitoring.poll_interval_seconds` — how often devices are pinged
- `web.noc_auto_refresh_seconds` / `web.auto_refresh_seconds` — public page refresh
- `security.token_expires_minutes` — admin session lifetime (default `480` = 8 hours; renewed on each manage-page request)
- `discovery.enabled` — when `false`, hides **Manage → Discover** and rejects CLI `discover`. Profiles and Refresh stay available (kill switch if a scan is mistaken for an attack)

Scan defaults and hard caps (`discovery:` in `config.yaml.example`):

| Setting | Default | Hard cap |
| --- | --- | --- |
| Max network | `/24` | `/24` (no `/23`) |
| Ping timeout | 1 s | 3 s |
| Ping concurrency | 32 | 64 |
| SNMP timeout | 2 s | 5 s |
| SNMP concurrency | 8 | 16 |
| Scan max runtime | 900 s | watchdog fails a stuck session |

After running the installation script, both files are created from example templates. Review them before using the system in production.

`inform-web` must remain a **single uvicorn worker**. The unit file does not pass `--workers`. Multiple workers would each hold their own in-process scan task; Cancel would only stop the worker that started the scan.

The monitor process pings via `/usr/bin/ping` (the `inform` user is unprivileged; Ubuntu `iputils-ping` has `cap_net_raw`). `inform/core/monitor.py` still has an unused `from icmplib import ping` leftover; discovery and monitoring do not use `icmplib`.

## Usage

### Management GUI (Recommended)

The web interface at `/manage` is the easiest way to manage buildings, devices, SNMP profiles, and discovery. Add buildings first; devices must be assigned to an existing building. SNMP is used only to identify vendor/model/name/location — **not** for Up / Down health.

### CLI Tools

```bash
cd /opt/inform-ng
sudo -u inform ./venv/bin/python -m inform.cli.main --help
```

Common commands:

- `create-admin`
- `add-device` (optional `--profile` fills SNMP identity after insert)
- `list-devices`
- `edit-device <ip>`
- `search-devices <term>`
- `add-profile` / `list-profiles` / `snmp-test`
- `refresh-snmp <ip>` (optional `--update-name`, `--profile` if none is linked)
- `discover <ip-or-cidr>` (optional repeatable `--profile`, `--confirm-public`; probe only, does not write devices)
- `export-inventory -o inventory.yaml`
- `import-inventory inventory.yaml` (optional `--dry-run`)

### Discover

**Manage → Discover** scans one IPv4 address or CIDR (max `/24`). INfoRM pings first, then SNMPs only live unmanaged hosts. Results appear in a review grid: check rows to add, edit name/location/building/comment/asset tag/monitored, and save. Already-managed IPs are listed as in inventory and are **never overwritten** — do not delete a device to pick up new SNMP fields; use Refresh instead. Zero credential profiles is allowed (ping-only). Public (non-RFC1918) targets require the **scan public space** checkbox (CLI: `--confirm-public`).

CLI `discover` is a probe: it prints a table and does **not** write `devices` or scan sessions.

The public **Devices** page (`/devices`) shows SNMP vendor and model in a compact **Vendor / Model** column after Location. Values longer than 20 characters are shortened; hover to see the full string. A dash means identity has not been filled yet (no profile, SNMP failed, or not yet refreshed). Search still matches the full vendor and model.

### SNMP identity and Refresh

SNMP is identity only (name, location, vendor, model). It does not decide Up / Pre-Alarm / Down.

**Manage → Devices** shows vendor and model as read-only fields. Identity is filled in these ways:

| Action | What happens |
| --- | --- |
| **Add Device** with a credential profile | Queries SNMP after save. Fills vendor, model, location, and name if name is blank. The device is kept even if SNMP fails. |
| **Refresh SNMP** on a table row | Uses the linked profile. Overwrites location, vendor, and model; fills a blank name. Hidden until a profile is linked. |
| **Refresh from SNMP** on the edit form | Same fields. Check **Also update name from sysName** to overwrite an existing name. If no profile is linked, pick one (or **Try all profiles**). |
| CLI `add-device --profile` / `refresh-snmp` | Same rules. `--update-name` overwrites name. `--profile` is required on refresh only when none is linked. |

SNMP never changes comment, building, asset tag, monitored, or IP. Assigning a profile on **Edit** and clicking **Update Device** does not query SNMP — use Refresh after that.

SNMPv3 `authPriv` (the default) needs the `cryptography` Python package for AES/DES. `pycryptodomex` only encrypts secrets at rest. A missing crypto backend used to look like a timeout.

### Credential profiles

**Manage → Profiles** stores SNMPv1 / v2c / v3 credentials used by Discover, Add Device, Refresh, and CLI `snmp-test` / `refresh-snmp`. Community, auth key, and priv key are encrypted at rest (AES-256-GCM, key from `SECURITY__SECRET_KEY`). The UI never echoes secrets (community is shown as set / not set). Deleting a profile unlinks devices; it does not delete devices. SNMPv3 defaults to authPriv with SHA + AES; those must match the device.

### Inventory backup / restore

Export buildings and devices to a YAML file from the management UI (**Export inventory**) or the CLI:

```bash
cd /opt/inform-ng
sudo -u inform ./venv/bin/python -m inform.cli.main export-inventory -o /tmp/inform-inventory.yaml
```

Import on the same or another INfoRM host. Existing building names and device IPs are skipped (same as `add-building` / `add-device`) — vendor, model, and profile on skipped IPs are not overwritten. Version 1 files still import (missing vendor/model/profile become empty). Version 2 files include those fields. An unknown `credential_profile` name still adds the device with the profile unset; the CLI reports `Profiles unresolved: N`. The file never contains community strings or keys.

`sys_object_id` is **omitted** from YAML. It is an internal cache used by Refresh. A restore without a later Refresh leaves `sys_object_id` NULL; vendor and model in the file are enough to display. Use **Refresh SNMP** if you want that cache filled.

```bash
sudo -u inform ./venv/bin/python -m inform.cli.main import-inventory --dry-run /tmp/inform-inventory.yaml
sudo -u inform ./venv/bin/python -m inform.cli.main import-inventory /tmp/inform-inventory.yaml
```

Example file shape:

```yaml
version: 2
buildings:
  - name: City Hall
    description: ""
devices:
  - ip_address: 10.0.0.1
    asset_tag: SW-001
    name: Core Switch
    building: City Hall
    location: MDF
    comment: ""
    monitored: true
    vendor: Cisco
    model: C9300-48P
    credential_profile: campus-v3
```

Admin sessions last 8 hours by default (`security.token_expires_minutes` in `config/config.yaml`) and renew while you are using the management pages.

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

**Logged out of `/manage` after about 15 minutes**  
You are on a build older than 1.1.3. Update and restart `inform-web`. Session length is `security.token_expires_minutes` (default 480).

**SNMPv3 `authPriv` times out; v2c works**  
pysnmp needs the `cryptography` package for AES/DES privacy. `pycryptodomex` only encrypts stored secrets. Re-run the installer, or:

```bash
sudo -u inform /opt/inform-ng/venv/bin/pip install -r /opt/inform-ng/requirements.txt
sudo systemctl restart inform-web
```

Also confirm the profile matches the device (username, SHA vs MD5 vs SHA-256, AES vs DES, keys). Wrong privacy protocol looks like a timeout because the agent drops the packet.

## Project Structure

```
INfoRM/
├── inform/                 # Core application logic
│   ├── cli/                # Command-line tools
│   ├── core/               # Database, models, monitoring, auth
│   ├── snmp/               # pysnmp client, identity, scan
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
Current version: 1.2.0
