# Security Policy

MicroLink puts devices on a private network, so security bugs matter a lot.
Thank you for helping keep users safe.

## Reporting a vulnerability

**Please do not open a public issue.**

Report privately via GitHub: **[Report a vulnerability](https://github.com/CamM2325/microlink/security/advisories/new)**
(Security tab → "Report a vulnerability").

Please include:
- affected commit/version and component (e.g. `wireguard_lwip`, `ml_coord`, `ml_derp`)
- impact and a minimal reproduction (a host-side test is ideal — see `test/host/`)
- whether the issue also affects upstream/forked projects and any coordinated disclosure date

## What to expect

| Step | Target |
|------|--------|
| Acknowledgement | within 7 days |
| Initial assessment | within 14 days |
| Fix or mitigation for high/critical issues | within 30 days, or on an agreed embargo date |

We are happy to join coordinated disclosure with other projects that share
code with MicroLink (e.g. `wireguard-lwip` derivatives). Reporters are credited
in the advisory and release notes unless they prefer otherwise.

## Supported versions

Only the latest release on `main` receives security fixes.

## Scope

In scope: the `microlink` and bundled `wireguard_lwip` components and the examples.
Out of scope: vulnerabilities in ESP-IDF, lwIP, mbedTLS, or Tailscale/Headscale
servers themselves (please report those upstream — we will help coordinate).
