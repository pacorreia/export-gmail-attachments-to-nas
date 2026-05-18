# export-gmail-attachments-to-nas

[![GitHub last commit](https://img.shields.io/github/last-commit/pacorreia/export-gmail-attachments-to-nas)](https://github.com/pacorreia/export-gmail-attachments-to-nas/commits/main)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/pacorreia/export-gmail-attachments-to-nas/blob/main/LICENSE)

## Description

`export-gmail-attachments-to-nas` is a self-hosted Go web service that automatically downloads Gmail attachments and saves them to one or more network shares (SMB) or local paths. Everything is configured through a browser UI — no config files or CLI flags required.

**Key features:**
- **Multiple Gmail accounts** — add accounts via Google OAuth2 in the UI
- **Multiple file shares** — SMB and local paths, with connection testing before save
- **Flexible rules** — Gmail query language, subfolder templates, and optional PDF→PNG conversion
- **Plugin system** — fire webhooks or run subprocesses when an attachment is saved
- **Run logs** — filterable history of every export run
- **SQLite by default** — zero-dependency storage; switchable to PostgreSQL or SQL Server

## Quick start with Docker

```bash
git clone https://github.com/pacorreia/export-gmail-attachments-to-nas.git
cd export-gmail-attachments-to-nas

# Set a strong random secret (required)
export SECRET_KEY=$(openssl rand -hex 32)

# Set your Google OAuth2 credentials
export GOOGLE_CLIENT_ID=your-client-id
export GOOGLE_CLIENT_SECRET=your-client-secret

docker compose up -d
```

Open **http://localhost:8080** in your browser.

> ⚠️ **Before production use:** replace the `SECRET_KEY` placeholder in `docker-compose.yml` with a strong random value. The secret encrypts stored OAuth tokens and SMB passwords.

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `SECRET_KEY` | ✅ | — | Encryption key for OAuth tokens and passwords (AES-256-GCM). The service will not start without it. |
| `DATABASE_URL` | ❌ | `sqlite:///data/app.db` | Database connection string. Prefix: `sqlite://`, `postgres://`, or `sqlserver://`. |
| `GOOGLE_CLIENT_ID` | ✅ | — | Google Cloud OAuth2 client ID |
| `GOOGLE_CLIENT_SECRET` | ✅ | — | Google Cloud OAuth2 client secret |
| `OAUTH_REDIRECT_URL` | ❌ | `http://localhost:8080/oauth/callback` | OAuth2 redirect URI (must match the Google Cloud console setting) |

See [docs/configuration.md](docs/configuration.md) for details on setting up Google OAuth2 credentials.

## Building from source

Go 1.22+ is required. No C compiler or CGO needed (uses a pure-Go SQLite driver).

```bash
go build -o server ./cmd/server
SECRET_KEY=changeme GOOGLE_CLIENT_ID=x GOOGLE_CLIENT_SECRET=x ./server
```

## Web UI pages

| Page | Purpose |
|---|---|
| **Accounts** | Add Gmail accounts via OAuth2 popup |
| **File Shares** | Add SMB or local destinations; test connection before saving |
| **Rules** | Build rules: Gmail query + subfolder template + PDF→PNG toggle; preview matching emails |
| **Plugins** | Configure webhook or subprocess plugins; test-fire against a sample event |
| **Run Logs** | Paginated history of exports, filterable by account, rule, and status |
| **Settings** | Scheduler interval, log retention period, database URL |

## Docs

- [docs/configuration.md](docs/configuration.md) — Google OAuth2 setup, environment variables, database backends
- [docs/rules.md](docs/rules.md) — Gmail query syntax, subfolder template variables
- [docs/plugins.md](docs/plugins.md) — Webhook and subprocess plugin reference

## Contributing

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Make your changes and run `go build ./...` to verify.
4. Commit your changes (`git commit -m 'Add some feature'`).
5. Push to the branch and open a pull request.

## License

This project is licensed under the MIT License — see the [LICENSE](./LICENSE) file for details.

## Author

* Paulo Correia — [pcportugal@gmail.com](mailto:pcportugal@gmail.com)