cert-manager

Command-line utility built with Go and Cobra, designed to manage SSL/TLS certificates across multiple targets through their respective APIs.
This document serves as the development backlog and technical overview of the features to be implemented.

Overview

The goal of cert-manager is to centralize the management of certificates for multiple systems (e.g., OPNsense) by allowing users to add, retrieve, update, and set active certificates via simple CLI commands.
All targets and credentials are defined in a .env file containing environment variables for each system:

<target_name>_key=<api_key>
<target_name>_secret=<api_secret>
<target_name>_url=<api_base_url>
<target_name>_type=<system_type>

TO DO – Core Features
1. Target Management

Command:

cert-manager add target -n <target_name> -k <key> -s <secret> -u <url> -t <type>


Description:
Allows users to add a new target system to the .env file, storing credentials and configuration details.
All parameters are mandatory.

Expected behavior:

Validate that the target name does not already exist.

Append new entries to .env in the required format.

Support update and delete subcommands for future versions.

TO DO:

Implement secure handling (avoid printing secrets to stdout).

Add validation for duplicate targets.

Implement .env file parser and writer module.

2. Certificate Retrieval

Command:

cert-manager get certificate expiration -t <target1,target2> | -A


Description:
Retrieves all certificates from specified targets or all (-A), and lists them with relevant metadata.

Example Output:

TargetName       CertificateName        ExpirationDate       CommonName
------------------------------------------------------------------------
OPNSense1        webgui-cert            2026-04-05           opnsense.local
OPNSense2        vpn-cert               2025-12-12           vpn.example.com


TO DO:

Parse the .env to identify selected targets.

Handle multiple target types (OPNSense, etc.).

Implement per-type API logic:

For OPNSense: /api/trust/certificates

Add formatting options (--json, --table).

3. Certificate Upload

Command:

cert-manager add certificate -t <target1,target2> -c <cert_file>


Description:
Uploads a new certificate to one or more targets using their API.

TO DO:

Validate certificate format (PEM, CRT, etc.).

Add handler for each target type:

For OPNSense: POST to /api/trust/certificates

Display summary after upload:

Target OPNSense1: Certificate uploaded successfully
Target OPNSense2: Error - Unauthorized

4. Certificate Metadata Management

Command:

cert-manager add certificate -c <cert_file> -k <key_file> -n <cert_name>


Description:
Adds a certificate to the local environment with metadata for later use (e.g., staging, synchronization).

TO DO:

Store the certificate details in a local database or structured file (e.g., JSON or SQLite).

Implement validation for unique certificate names.

5. Set SSL for WebGUI

Command:

cert-manager set-ssl -t <target>


Description:
Fetches the list of available certificates from the target and allows the user to select which one to use for the system’s WebGUI.

Expected Flow:

Fetch /api/trust/certificates.

Present a selectable list of certificates.

User selects one.

Perform API call to set WebGUI certificate.

TO DO:

Implement interactive selection (using Cobra prompt or TUI).

Define API endpoint per target type for setting the active cert.

For OPNSense: likely /api/system/webgui

Handle success/failure messages cleanly.

TO DO – Enhancements
6. Environment Management

Support multiple .env profiles (e.g., --env staging.env).

Add cert-manager list targets to quickly view configured systems.

7. Error Handling

Implement standardized error responses.

Include retries for transient API errors.

8. Logging and Output

Add --verbose and --debug flags.

Support JSON output for automation pipelines.

9. Security

Encrypt .env secrets using AES or external key storage (future phase).

Prevent credentials from appearing in logs.

10. Testing and CI

Unit tests for .env parser, API clients, and CLI handlers.

Integration tests for OPNsense-type targets.

Optional: GitHub Actions workflow for linting, tests, and builds.

Architecture (TO DO)

Modules:

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


TO DO:

Implement modular structure for maintainability.

Create unified API interface for all supported systems.

Future Features (Backlog)

cert-manager renew – Automated renewal and re-upload.

cert-manager sync – Sync local and remote certs.

cert-manager validate – Validate certificate chain and expiration.

Integration with external CAs (e.g., Let’s Encrypt, AWS ACM).

TUI dashboard for target overview.
