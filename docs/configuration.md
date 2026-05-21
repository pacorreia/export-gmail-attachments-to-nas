# Configuration

## Google OAuth2 setup

The service uses Google OAuth2 to access Gmail on behalf of your accounts. You need a Google Cloud project with the Gmail API enabled.

### 1. Create a Google Cloud project

1. Go to [console.cloud.google.com](https://console.cloud.google.com).
2. Create a new project (or select an existing one).
3. Navigate to **APIs & Services → Library** and enable the **Gmail API**.

### 2. Create OAuth2 credentials

1. Go to **APIs & Services → Credentials**.
2. Click **Create Credentials → OAuth client ID**.
3. Choose **Web application**.
4. Under **Authorised redirect URIs** add:
   - `http://localhost:8080/oauth/callback` (for local development)
   - Your production URL if deployed remotely, e.g. `https://nas.example.com/oauth/callback`
5. Copy the **Client ID** and **Client Secret**.

### 3. Configure the OAuth consent screen

1. Go to **APIs & Services → OAuth consent screen**.
2. Choose **External** (or **Internal** if using Google Workspace).
3. Fill in the app name and support email.
4. Add the scope `https://mail.google.com/` under **Scopes**.
5. Add the Gmail addresses you want to export from under **Test users** (required while the app is in testing mode).

---

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `SECRET_KEY` | ✅ | — | A strong random string used to derive the AES-256-GCM encryption key for OAuth tokens and SMB passwords. The service will **not start** if this is unset. Generate with: `openssl rand -hex 32` |
| `DATABASE_URL` | ❌ | `sqlite:///data/app.db` | Database connection string (see below). |
| `PORT` | ❌ | `8080` | HTTP port the server listens on. |
| `GOOGLE_CLIENT_ID` | ✅ | — | OAuth2 client ID from Google Cloud Console |
| `GOOGLE_CLIENT_SECRET` | ✅ | — | OAuth2 client secret from Google Cloud Console |
| `OAUTH_REDIRECT_URL` | ❌ | `http://localhost:8080/oauth/callback` | Must match the redirect URI registered in Google Cloud Console |

---

## Database backends

The `DATABASE_URL` prefix selects the backend:

| Prefix | Backend | Notes |
|---|---|---|
| `sqlite://` | SQLite (default) | Pure-Go driver, no C compiler needed. DB file created automatically. |
| `postgres://` | PostgreSQL | Standard libpq DSN, e.g. `postgres://user:pass@host:5432/dbname` |
| `sqlserver://` | SQL Server / Azure SQL | e.g. `sqlserver://user:pass@host:1433?database=dbname` |

Schema migrations run automatically on startup via GORM `AutoMigrate`.

### SQLite example (default)
```
DATABASE_URL=sqlite:///data/app.db
```
The `/data` directory is mapped to a Docker volume in the provided `docker-compose.yml`.

### PostgreSQL example
```
DATABASE_URL=postgres://myuser:mypassword@postgres:5432/gmail_exporter
```

---

## Docker Compose

The provided `docker-compose.yml` is the recommended way to run the service:

```yaml
services:
  app:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./data:/data
    environment:
      DATABASE_URL: sqlite:///data/app.db
      SECRET_KEY: changeme          # ⚠ Replace with a strong random value!
      GOOGLE_CLIENT_ID: ""
      GOOGLE_CLIENT_SECRET: ""
      OAUTH_REDIRECT_URL: http://localhost:8080/oauth/callback
```

Replace `changeme` with the output of `openssl rand -hex 32` before deploying.

---

## Running behind a reverse proxy

If you run the service behind nginx or Traefik, ensure:

1. The `OAUTH_REDIRECT_URL` matches the public-facing URL.
2. The reverse proxy passes the `Host` and `X-Forwarded-*` headers through.
3. HTTPS is used in production (required by Google for non-localhost redirect URIs).
