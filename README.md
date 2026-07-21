# Wazuh Journal

> An English-first SOC workspace for triaging live Wazuh alerts, investigating individual events with AI, and preparing Wazuh rule drafts.

[![License](https://img.shields.io/badge/license-non--commercial-orange.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D22.13.0-339933.svg?logo=node.js&logoColor=white)](https://nodejs.org/)

Wazuh Journal turns a stream of Wazuh alerts into a focused investigation workflow. Alerts are grouped into five-minute batches, individual events can be sent to an OpenAI-compatible API for false-positive triage, and generated XML rules are kept as drafts until an operator explicitly adds them.

The interface is English by default and includes a persistent `EN / RU` language switch. It does not invent demo events: when Wazuh is unavailable, the UI shows the integration error instead of fabricating data.

## Contents

- [Highlights](#highlights)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Production deployment](#production-deployment)
- [Available scripts](#available-scripts)
- [Security](#security)
- [Current limitations](#current-limitations)
- [Contributing](#contributing)
- [License](#license)

## Highlights

- Live Wazuh alert feed through a server-side SSH bridge.
- Five-alert batch grouping with severity, host, time, and rule metadata.
- Filters for severity, time range, marked alerts, and skipped alerts.
- Single-alert AI analysis through any OpenAI-compatible `/chat/completions` endpoint.
- False-positive probability, explanation, summary, and XML rule draft review.
- Analysis history with unread state and quick return to the original alert.
- Local Wazuh rule editor with XML scope protection and backup-on-save behavior.
- Optional LDAP/Active Directory-compatible authentication flow.
- Local settings panel for Wazuh, jump-host, LDAP, and AI integration values.
- English-first UI with Russian localization.
- Cloudflare Sites-compatible build configuration.

## Architecture

The project is a Next.js/React application with server-side integration routes:

```text
Browser
  │
  ├── Feed, filters, language switch, analysis history
  │
  ▼
Next.js API routes
  ├── Wazuh SSH bridge ──► Wazuh Indexer
  ├── Authentication ─────► Wazuh / LDAP / AD-compatible identity source
  ├── AI analysis ────────► OpenAI-compatible API
  └── Rule operations ────► Protected Wazuh Manager workflow
```

Secrets are read and used on the server. They are never intended for client bundles, `public/`, or browser storage. Device-local browser storage is used only for UI preferences, marks, skipped alerts, and unread analysis state.

## Requirements

- Node.js `>=22.13.0`
- npm
- A reachable Wazuh deployment for live data
- SSH credentials with the minimum permissions required by your Wazuh commands
- An OpenAI-compatible provider if AI analysis is required

## Quick start

```bash
git clone https://github.com/Hamronov/Wazuh-Journal.git
cd Wazuh-Journal
npm ci
cp .env.example .env.local
npm run dev
```

Open the local URL printed by the development server. Sign in with the configured Wazuh/domain account, then open **Settings** to verify integrations.

AI analysis is optional. If `OPENAI_*` variables are not configured, the feed remains available and the AI panel reports that the integration is not configured.

## Configuration

`.env.example` is a safe template. Copy it to `.env.local` for local work and replace every value with environment-specific settings. Never commit `.env.local` or real credentials.

### Wazuh and SSH

| Variable | Purpose |
| --- | --- |
| `WAZUH_SSH_HOST` | Wazuh SSH host or tunnel endpoint. |
| `WAZUH_SSH_PORT` | SSH port, usually `22`. |
| `WAZUH_SSH_USER` | SSH user for the Wazuh bridge. |
| `WAZUH_SSH_PRIVATE_KEY` | Private key contents; keep server-side only. |
| `WAZUH_SSH_PRIVATE_KEY_PATH` | Server-side path to a private key. |
| `WAZUH_SSH_PASSWORD` | Password alternative to a private key. |
| `WAZUH_SSH_JUMP_HOST` | Optional bastion/jump host. |
| `WAZUH_SSH_JUMP_PORT` | Optional bastion port. |
| `WAZUH_SSH_JUMP_USER` | Optional bastion user. |

### Authentication and directory services

| Variable | Purpose |
| --- | --- |
| `AUTH_SESSION_SECRET` | Session-signing secret. Required in production; use a random value of at least 32 characters. |
| `AUTH_COOKIE_SECURE` | Keep `true` for HTTPS. Set to `false` only for trusted LAN deployments that must use plain HTTP. |
| `AD_TENANT_ID` | Optional Active Directory tenant identifier. |
| `AD_CLIENT_ID` | Optional directory application identifier. |
| `AD_CLIENT_SECRET` | Optional directory application secret. |
| `LDAP_SERVER_URIS` | Comma-separated LDAP/LDAPS server URIs. |
| `LDAP_BASE_DN` | Directory base DN. |
| `LDAP_BIND_DN` | Service bind DN. |
| `LDAP_BIND_PASSWORD` | Service bind password. |
| `LDAP_USERS_DNS` | Semicolon-separated user search DNs. |
| `LDAP_GROUPS_DN` | Group search DN. |
| `LDAP_CA_CERT` | Optional CA certificate for LDAPS validation. |

### AI provider

| Variable | Purpose |
| --- | --- |
| `OPENAI_BASE_URL` | Provider base URL, for example `https://api.openai.com/v1`. |
| `OPENAI_API_KEY` | Provider API key; never expose it to the browser. |
| `OPENAI_MODEL` | Model name used for one-alert analysis. |

The analysis endpoint sends only the selected alert (or an explicitly selected batch) to the configured provider. It does not send the entire feed.

## Production deployment

Build and run with the standard Node.js workflow:

```bash
npm ci
npm run build
npm start
```

For Cloudflare Sites, keep `.openai/hosting.json` in the repository and configure runtime secrets in the hosting environment rather than Git. Set `AUTH_SESSION_SECRET` and all Wazuh/directory/AI values required by your deployment before allowing users to sign in.

Before publishing a build, run:

```bash
npm run lint
npm test
```

## Available scripts

| Command | Description |
| --- | --- |
| `npm run dev` | Start the local development server. |
| `npm run build` | Create the production build. |
| `npm start` | Run the production server. |
| `npm run lint` | Run ESLint and the production-data safety check. |
| `npm test` | Build the project and run the rendered/source contract tests. |
| `npm run check:production-data` | Ensure prohibited fixture markers are not shipped in application code. |
| `npm run db:generate` | Generate Drizzle metadata when database schema work is required. |

## Security

Read [SECURITY.md](SECURITY.md) before configuring integrations.

- Do not commit `.env.local`, private keys, passwords, API keys, or certificates.
- Keep Wazuh, LDAP, AD, and AI credentials on the server side.
- Use a strong random `AUTH_SESSION_SECRET` in production.
- Treat generated XML as a draft: validate syntax, scope, and impact before applying it to Wazuh.
- Audit production rule writes and restrict the account used by the rule-management backend.
- Rotate any credential that is accidentally exposed before removing it from files or history.

## Current limitations

This repository is a deployable foundation, not a complete managed SOC platform. Depending on the target environment, the following still require operational setup:

- Wazuh SSH bridge connectivity and least-privilege command configuration;
- production LDAP/Active Directory authorization and access policy;
- durable analysis-history storage and database migrations;
- audited production rule writes through a protected backend;
- provider-specific AI privacy, retention, and model policies.

No test alerts are substituted when Wazuh is unavailable.

## Contributing

1. Create a branch from `main`.
2. Keep secrets and organization-specific infrastructure details out of commits.
3. Preserve the English-first interface and update the Russian translation when adding user-facing copy.
4. Run `npm run lint` and `npm test` before opening a pull request.
5. Describe security impact and deployment implications for integration changes.

## License

Wazuh Journal is source-available for personal, educational, research, and other non-commercial use under the custom [Wazuh Journal Non-Commercial License](LICENSE).

Commercial use, including SaaS, paid products, managed services, and business operations, requires separate written permission from the copyright holder.
