# Security policy

## Supported versions

`rootcause-server` is currently an early foundation release. Security fixes are
applied to the latest tagged version and to the default branch.

## Reporting a vulnerability

Do not open public issues containing exploit details, credentials, private IP
addresses, logs, personal data, or customer information. Use GitHub's private
security advisory flow for the repository owner.

Include the affected version, operating system, reproduction steps, impact,
and a minimal proof of concept. Allow a reasonable remediation window before
public disclosure.

## Operational baseline

- Keep the API token secret and rotate it after suspected exposure.
- Bind to loopback by default. Use a trusted TLS reverse proxy for remote use.
- Never expose the SQLite database or administrative port directly to Internet.
- Run the service with a dedicated, least-privileged account.
- Review every guided response before execution.
- Preserve audit logs and encrypted backups.

RootCause complements endpoint protection, EDR, SIEM, firewalls and operating
system security controls. It does not replace them.
