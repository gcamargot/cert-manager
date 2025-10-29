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

## Core Features

### 1. Target Management

**Command**

```
cert-manager add target -n <target_name> -k <key> -s <secret> -u <url> -t <type>
```

**Description**  
Adds a new target system to `.env`, persisting credentials and configuration details. All parameters are mandatory.

**Expected behavior**
- Validate that the target name does not already exist.
- Append new entries to `.env` in the required format.
- Prepare groundwork for future `update` and `delete` subcommands.

**TO DO**
- Avoid printing secrets to stdout.
- Add stronger duplicate validation.
- Extract `.env` parsing/writing to dedicated helpers.

### 2. Certificate Retrieval *(WIP)*

**Command**

```
cert-manager get certificate expiration -t <target1,target2> | -A
```

**Description**  
Retrieves certificates for the selected targets (or all with `-A`) and prints metadata.

**Example output**

```
TargetName       CertificateName        ExpirationDate       CommonName
------------------------------------------------------------------------
OPNSense1        webgui-cert            2026-04-05           opnsense.local
OPNSense2        vpn-cert               2025-12-12           vpn.example.com
```

**TO DO**
- Parse `.env` to resolve target selections.
- Support multiple target types (OPNSense, etc.).
- Implement per-type API calls (OPNSense: `/api/trust/certificates`).
- Provide `--json` and `--table` formatting options.

### 3. Certificate Upload

**Command**

```
cert-manager upload certificate -t <target1,target2> -c <cert_file>
cert-manager upload certificate -t <target1,target2> -a <alias_registrado>
```

**Description**  
Uploads a new certificate to one or more targets via their API. The command accepts either a PEM bundle, separate certificate/key files, or an alias previously registered with `cert-manager add certificate`.

**TO DO**
- Validate certificate formats (PEM, CRT, etc.).
- Add handlers per target type (OPNSense: `POST /api/trust/certificates`).
- Summarize results per target (success/error).

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
Shows the locally stored certificates with their common name, country, expiration date, and file path, refreshing metadata from disk.

**TO DO**
- Persist metadata in a structured store (JSON or SQLite).
- Enforce unique certificate names.

### 7. Set SSL for WebGUI

**Command**

```
cert-manager set-ssl -t <target>
```

**Description**  
Fetches certificates from a target and lets the user choose which one to apply to the system WebGUI.

**Expected flow**
- Fetch `/api/trust/certificates`.
- Present selectable list to the user.
- Send the API call to set the WebGUI certificate.

**TO DO**
- Implement interactive selection (Cobra prompt or TUI).
- Define per-target endpoint (OPNSense: likely `/api/system/webgui`).
- Improve success/failure messaging.

## Enhancements

### 8. Environment Management
- Support multiple `.env` profiles (e.g., `--env staging.env`).
- Add `cert-manager list targets` to view configured systems quickly.

### 9. Error Handling
- Standardize error responses.
- Retry transient API errors.

### 10. Logging and Output
- Add `--verbose` and `--debug` flags.
- Provide JSON output for automation pipelines.

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
