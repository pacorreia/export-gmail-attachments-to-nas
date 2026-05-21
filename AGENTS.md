# Agent Guidelines — export-gmail-attachments-to-nas

## Architecture

Single-binary Go server (`cmd/server/`) that serves both the REST API and the embedded SolidJS frontend on one port.

```
cmd/server/          entry point
internal/
  crypto/            AES encryption/decryption for secrets at rest
  db/                GORM init; models in db/models/models.go
  fileshare/         SMB and local filesystem operations
  gmail/             Gmail API client + OAuth callback handler
  pdf/               PDF-to-image conversion
  plugin/            plugin execution engine
  scheduler/         cron-style job scheduler
  web/
    server.go        router ONLY — no logic, no inline handlers
    handlers/        one .go file per resource domain
    frontend/        SolidJS app (built to frontend/dist/, embedded via go:embed)
tests/               e2e tests (httptest + in-memory SQLite)
```

## Non-Negotiable Rules

### SRP in `internal/web/`
`server.go` is a pure router. Every handler lives in `internal/web/handlers/`. No inline `func(w, r)` closures in `server.go` — ever.

One handler file per domain:
- `health.go`, `accounts.go`, `fileshares.go`, `rules.go`, `plugins.go`, `logs.go`, `settings.go`
- `helpers.go` holds only `writeJSON` and `writeError`

When adding a new route, the pattern is:
1. Create/update the handler in `handlers/<domain>.go`
2. Register the route in `server.go`

### Secrets at rest
Sensitive values (SMB passwords, tokens) are **always** stored encrypted via `internal/crypto`. Model fields that hold encrypted data use `json:"-"`. The plain value is never persisted. When editing password fields, only re-encrypt if the incoming value is non-empty (to allow edits without re-entering the password).

### GORM models
All models embed `gorm.DeletedAt` (soft-delete). Sensitive fields are tagged `json:"-"`. All models are defined in `internal/db/models/models.go`.

### Frontend conventions (SolidJS)
- All HTTP calls go through `src/api.js` (`api(path, opts)`) — never `fetch` directly.
- Toast notifications via `useToast()` context; modals via `useModal()` context.
- Forms support both create and edit modes via a `props.share` / `props.rule` etc. prop — branch on its presence to choose POST vs PUT.
- New pages go in `src/pages/`, new reusable UI in `src/components/`.

## Build & Run

```bash
# Backend
go build ./...
go test ./...

# Frontend (requires Node 24 — project ships a .nvmrc)
source ~/.nvm/nvm.sh && nvm use
cd internal/web/frontend
npm run build          # outputs to frontend/dist/ (embedded at compile time)

# Local dev server
SECRET_KEY=dev-local-secret DATABASE_URL="sqlite://$(pwd)/data/app.db" PORT=9090 \
  go run ./cmd/server/...
```

## Testing

- **Handler unit tests**: `internal/web/handlers/*_test.go` — use `net/http/httptest`, shared setup in `testmain_test.go`
- **E2E tests**: `tests/e2e_test.go` — full HTTP stack, in-memory SQLite, no external services
- Run all: `go test ./...`
- Tests must not contact Gmail, SMB, or any external network

## Environment Variables

| Variable       | Required | Description                                                     |
|----------------|----------|-----------------------------------------------------------------|
| `SECRET_KEY`   | yes      | Key for `internal/crypto` AES encryption                       |
| `DATABASE_URL` | no       | `sqlite://`, `postgres://`, or `sqlserver://` (default: sqlite) |
| `PORT`         | no       | HTTP listen port (default: `8080`)                              |

## Adding a New Resource (Checklist)

1. Add model struct to `internal/db/models/models.go`
2. Add to `db.AutoMigrate(...)` call in `internal/db/db.go`
3. Create `internal/web/handlers/<resource>.go` with CRUD handlers
4. Register routes in `internal/web/server.go`
5. Create `src/pages/<Resource>.jsx` with list + create/edit form
6. Add page route in `src/App.jsx`
7. Add handler tests in `internal/web/handlers/<resource>_test.go`
