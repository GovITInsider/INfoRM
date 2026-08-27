## [Unreleased]

### Added
- Manual **Add Device** with a credential profile now queries SNMP and fills vendor, model, location, and a blank name
- **Refresh SNMP** on each row of Manage → Devices (uses the device's linked profile)
- CLI `refresh-snmp <ip>` (`--update-name`, optional `--profile`)

### Changed
- Refresh from SNMP fills a blank device name even when **Also update name from sysName** is unchecked
- CLI `add-device --profile` fills SNMP identity after insert

### Fixed
- SNMPv3 `authPriv` failed with a timeout: pysnmp needs the `cryptography` package for AES/DES privacy. `pycryptodomex` is only used for secrets at rest. A missing crypto backend is no longer reported as a timeout.

## [1.2.0] - 2026-08-26

### Added
- On-demand **Manage → Discover**: scan one IPv4 or CIDR (max `/24`), ping then SNMP, review grid, bulk-add selected hosts
- **Manage → Profiles** for SNMPv1 / v2c / v3 credentials (create / edit / test / delete); CLI `add-profile` / `list-profiles` / `snmp-test` / `discover`
- Per-device **Refresh from SNMP** on the management Devices page (location, vendor, model; name only if asked)
- SNMP vendor and model on the management device table and edit form (read-only)
- Compact Vendor / Model column on the public Devices page (truncated at 20 characters; hover for the full value)
- Inventory YAML **version 2**: export/import `vendor`, `model`, and `credential_profile` (profile name, never secrets)
- AES-256-GCM encryption of community / auth / priv secrets at rest (key derived from `SECURITY__SECRET_KEY`)

### Changed
- SNMP identity uses pysnmp 7.1 asyncio instead of subprocess `snmpget`
- SQLite uses WAL, `BEGIN IMMEDIATE`, and database file mode `0640`
- Inventory import still skips existing IPs; unknown profile names add the device with the profile unset (`Profiles unresolved: N`)

### Notes
- Up / Pre-Alarm / Down remain ICMP. SNMP is identity only.
- `sys_object_id` is omitted from inventory YAML (internal refresh cache)
- `discovery.enabled: false` hides Discover and rejects CLI `discover`; Profiles and Refresh stay available
- `inform-web` must stay a single uvicorn worker (no `--workers`)
- Rotating `SECURITY__SECRET_KEY` invalidates sessions and encrypted profile secrets

## [1.1.3] - 2026-08-25

### Added
- YAML inventory export/import for buildings and devices (`export-inventory` / `import-inventory`, plus **Export inventory** in the management UI)
- Sliding admin sessions: each manage-page request renews the cookie

### Fixed
- Admin login expired after 15 minutes (fastapi-login default). `security.token_expires_minutes` (default 480 / 8 hours) is now applied to the JWT and cookie

## [1.1.2] - 2026-08-25

### Added
- systemd unit files for `inform-web` and `inform-monitor`
- Python 3.12+ version check and OS package install in `scripts/install.sh` (Ubuntu 24.04 / 26.04)
- Install troubleshooting notes in the README

### Fixed
- Installer now locates the project root from the script path, so `sudo bash scripts/install.sh` works from any directory
- Database initialization imports models before `create_all()`, so tables (including `users`) are actually created
- Restored the management Devices page (it had been overwritten with the public Device Dashboard)
- Added `python-multipart` and pinned `bcrypt` to a passlib-compatible 4.0.x range
- `edit-device` CLI no longer crashes on a `devide.comment` typo

### Changed
- First-time install generates a random `SECURITY__SECRET_KEY` in `.env`

## [1.1.1] - 2026-08-11

### Changed
- Asset Tag column now displays a maximum of 12 characters (full value shown on hover)
- Improved search on both the public Devices page and Management Devices page so truncated fields (Asset Tag and Comment) remain fully searchable
- Standardized the client-side search JavaScript between the public and management Devices pages

### Fixed
- Search no longer fails to find text that is hidden due to column truncation
