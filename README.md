# cert-manager

Command-line utility built with Go and Cobra to manage SSL/TLS certificates across multiple targets via their APIs.  
This document doubles as a technical overview and development backlog.

## Overview

The goal is to centralize certificate management for multiple systems (e.g., OPNsense) by adding, retrieving, updating, and activating certificates through CLI commands.

Targets and credentials are stored in a `.env` file using the following convention:

```
<target_name>_key=<api_key>
<target_name>_secret=<api_secret>
<target_name>_url=<api_base_url>
<target_name>_type=<system_type>
```

The CLI keeps a plain-text `targetlist` file (one target name per line). `cert-manager add target` updates both files so subsequent runs load the new entry automatically.

## Core Features

### 1. Target Management

**Command**

```
cert-manager add target -n <target_name> -k <key> -s <secret> -u <url> -t <type>
```

**Description**  
Adds a new target system to `.env`, persisting credentials and configuration details. All parameters are mandatory.

**Expected behavior**
- Validate that the target name does not already exist (both in-memory and on disk).
- Append new entries to `.env` in the required format and update the `targetlist` file used at startup.
- Refresh the in-memory target registry so subsequent commands can use the new target immediately.

**TO DO**
- Avoid printing secrets to stdout.
- Add `update`/`delete` flows for existing targets.
- Extract `.env` parsing/writing to dedicated helpers.

### 2. Certificate Retrieval

**Command**

```
cert-manager get certificate expiration -t <target1,target2> | -A
```

**Description**  
Retrieves certificates for the selected targets (or all with `-A`) and prints metadata for each remote system.  
- Output defaults to a colorized ASCII table that highlights the active certificate (`*` in the `Active` column) and paints expiration dates green (valid), red (expired) or gray (inactive certificates).  
- `--output json` is available for scripting-friendly consumption.  
- Currently implemented for OPNsense targets via `/api/trust/cert/search` plus `/api/system/webgui/get` to detect the WebGUI certificate in use.

**Example output**

```
+----------+-------------------+---------------------+----------------------+--------+
| Target   | Certificate       | Expiration          | CommonName           | Active |
+----------+-------------------+---------------------+----------------------+--------+
| OPNsense | WebGUI cert       | 2026-04-05 12:00:00 | opnsense.local       | *      |
| OPNsense | VPN backup cert   | 2025-12-12 08:30:00 | vpn.example.com      |        |
+----------+-------------------+---------------------+----------------------+--------+
```

### 3. Certificate Upload

**Command**

```
cert-manager upload certificate -t <target1,target2> -c <cert_file>
cert-manager upload certificate -t <target1,target2> -a <alias_registrado>
```

**Description**  
Uploads a new certificate to one or more targets. Sources supported:
- Direct PEM bundle (`--cert`), optionally accompanied by a private key (`--key`).
- A previously registered alias (`--alias`) created with `cert-manager add certificate`.

Only OPNsense targets are supported today. The command parses metadata, enforces mandatory country codes, and posts to `/api/trust/cert/add`.

**TO DO**
- Extend upload handlers to other target types.
- Improve per-target reporting and rollback on partial failures.

### 4. Certificate Metadata Management

**Command**

```
cert-manager add certificate -c <cert_file> -k <key_file> -n <cert_name>
```

**Description**  
Stores certificate metadata locally for staging and synchronization workflows.

**Notes**
- Requires specifying the country code (`--country`) when the certificate does not include it.
- Certificates are stored under `~/.cert-manager/certificates.json` and can later be reused with `cert-manager upload certificate -a <alias>`.
- A copia del PEM original se almacena en `~/.cert-manager/<alias>.pem` para integraciones posteriores.
- Duplicate aliases are prevented (`add certificate` refuses duplicates).

### 5. Certificate Update

**Command**

```
cert-manager update certificate -n <cert_name> -c <cert_file> [-k <key_file>] [--country <code>]
```

**Description**
Updates a previously registered certificate by backing up the old PEM under `~/.cert-manager/backups/` (including the prior expiration date in the filename) and refreshing the local metadata with the new file paths, CN, expiration, and country.

### 6. Certificate Inventory

**Command**

```
cert-manager list certificates
```

**Description**  
Shows the locally stored certificates with their common name, country, expiration date, file path, and current parsing status. The command refreshes metadata from disk before printing and persists any corrections back to `~/.cert-manager/certificates.json`.

### 7. Set SSL for WebGUI

**Command**

```
cert-manager set-ssl -t <target>
```

**Description**  
Fetches certificates from a target and lets the user choose (interactively or via `--cert`) which one to apply to the system WebGUI. Requires WebGUI credentials (`-u/-p` flags or prompts) because the operation manipula la configuración a través de `diag_backup.php`.

**Current flow**
- Authenticate against the OPNsense WebGUI (session API + legacy login fallback).
- Download the current `config.xml` (POST + GET fallback), update `<ssl-certref>` and re-upload it with CSRF protection.
- After restoration, wait for the appliance to come back online by pinging (up to 5 min) and verify the applied certificate by re-downloading the configuration.
- Verbose mode (`-v`) surfaces detailed progress and diagnostics.
- WebGUI credentials se obtienen automáticamente del entorno (`<target>_user` / `<target>_pw`) o de las flags `--username/--password`. Use `--login` (`-l`) para forzar el ingreso interactivo.

**TO DO**
- Implement the pending `--gui` simulation mode.
- Improve detection of WebGUI availability beyond ICMP (e.g., HTTPS health checks).
- Support additional target types beyond OPNsense.

## Enhancements

### 8. Environment Management
- Support multiple `.env` profiles (e.g., `--env staging.env`).
- Add `cert-manager list targets` to view configured systems quickly.

### 9. Error Handling
- Standardize error responses.
- Retry transient API errors.

### 10. Logging and Output
- `--verbose` flag already surfaces detailed HTTP flow (e.g., `set-ssl`). Consider adding `--debug` for wire-level tracing.
- Extend colorized/table output to other commands and provide a `--no-color` escape hatch.

### 11. Security
- Encrypt `.env` secrets (AES or external storage).
- Prevent credentials from appearing in logs.

### 12. Testing and CI
- Unit tests for `.env` parsing, API clients, and CLI handlers.
- Integration tests for OPNsense targets.
- Optional GitHub Actions for linting, tests, and builds.

## Architecture (Planned)

```
cmd/
  ├── root.go
  ├── add.go
  ├── get.go
  ├── set_ssl.go
internal/
  ├── env/
  │   ├── parser.go
  │   └── writer.go
  ├── api/
  │   ├── opnsense.go
  │   └── ...
  └── utils/
      ├── formatter.go
      └── logger.go
```

**TO DO**
- Implement modular structure for maintainability.
- Create a unified API interface across system types.

## Future Features (Backlog)
- `cert-manager renew` – Automated renewal and re-upload.
- `cert-manager sync` – Sync local and remote certs.
- `cert-manager validate` – Validate certificate chain and expiration.
- Integrations with external CAs (Let’s Encrypt, AWS ACM, etc.).
- TUI dashboard for target overview.
