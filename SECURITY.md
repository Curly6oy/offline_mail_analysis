# Security Policy

## Supported release

Security fixes are prioritized for the latest stable release.

## Reporting a vulnerability

Do not include real email contents, personal data, credentials, or secrets in an issue.

For a sensitive report, contact the repository owner privately through GitHub and provide:
- affected version;
- minimal reproduction steps;
- expected and actual behavior;
- impact assessment;
- sanitized logs or sample data.

## Offline security model

The application is designed so the analyzer does not make HTTP, DNS, or API requests and does not persist uploaded email contents.

For high-assurance deployments, additionally isolate the host and restrict outbound network traffic at the operating-system or firewall level.

## Secrets

Never commit `.env`, production password hashes, session secrets, real `.eml` files, or customer data.
