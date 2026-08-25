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
